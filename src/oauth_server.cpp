// Copyright Eduard Marin, November 2023

#include "oauth.h"
#include "oauth_server.h"
#include "token.h"
#include "utils.h"

#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <unordered_set>
#include <vector>
#include <unordered_map>
#include <iostream>

// In-memory databases
std::unordered_map<std::string, user_data> users;				// user_id -> user_data
std::unordered_map<std::string, std::string> auth_tokens;		// auth_token -> user_id
std::unordered_map<std::string, std::string> access_tokens;		// access_token -> user_id
std::unordered_map<std::string, std::string> refresh_tokens;	// refresh_token -> user_id
std::unordered_set<std::string> resources;
std::vector<std::unordered_map<std::string, std::string>> approvals;

int tokens_validity;
int approvals_index = 0;

void server_init(server_init_props *props) {
	tokens_validity = props->tokens_validity;

	std::vector<std::string> clients_lines;
	get_lines_from_file(props->clients_file, true, clients_lines);

	for (int i = 0; i < clients_lines.size(); ++i) {
		users[clients_lines[i]] = (user_data) {
			.authorization_token = 0,
			.access_token = 0,
			.refresh_token = 0,
			.num_operations = tokens_validity,
			.auto_refresh = false,
			.authorized = false
		};
	}

	std::vector<std::string> resources_lines;
	get_lines_from_file(props->resources_file, true, resources_lines);

	for (int i = 0; i < resources_lines.size(); ++i) {
		resources.insert(resources_lines[i]);
	}

	std::vector<std::string> permissions_lines;
	get_lines_from_file(props->permissions_file, false, permissions_lines);

	for (int i = 0; i < permissions_lines.size(); ++i) {
		std::string line = permissions_lines[i];
		approvals.push_back(std::unordered_map<std::string, std::string>());

		int comma_pos = 0;
		std::vector<std::string> permission;

		for (int j = 0; j < line.size(); ++j) {
			if (line[j] == ',') {
				permission.push_back(line.substr(comma_pos, j - comma_pos));
				comma_pos = j + 1;

				if (permission.size() == 2) {
					approvals[i][permission[0]] = permission[1];
					permission.clear();
				}
			}
		}

		// If the last character on the line is not ','
		if (permission.size() > 0) {
			approvals[i][permission[0]] = line.substr(comma_pos);
			permission.clear();
		}
	}
}

request_authorization_res *
request_authorization_1_svc(request_authorization_props arg1,  struct svc_req *rqstp)
{
	static request_authorization_res result;

	std::cout << "BEGIN " << arg1.client_id << " AUTHZ" << std::endl;

	if (users.find(arg1.client_id) == users.end()) {
		result.err = USER_NOT_FOUND;
	} else {
		result.err = 0;

		char *authorization_token = generate_access_token(arg1.client_id);

		result.request_authorization_res_u.token = authorization_token;

		users[arg1.client_id].authorization_token = authorization_token;
		users[arg1.client_id].auto_refresh = arg1.auto_refresh;
		users[arg1.client_id].num_operations = tokens_validity;

		auth_tokens[authorization_token] = arg1.client_id;

		std::cout << "  RequestToken = " << authorization_token << std::endl;
	}

	return &result;
}

approve_request_token_res *
approve_request_token_1_svc(approve_request_token_props arg1,  struct svc_req *rqstp)
{
	static approve_request_token_res result;

	// Check if the user allows the client to assume the permissions
	// for the current token
	result.was_signed = approvals[approvals_index][ALL] != DENY_PERMISSION;

	// Store the result
	users[auth_tokens[arg1.authorization_token]].authorized = result.was_signed;
	users[auth_tokens[arg1.authorization_token]].permissions = approvals[approvals_index];

	// Update the index of the current approval in FIFO order
	approvals_index += 1;

	return &result;
}

request_access_token_res *
request_access_token_1_svc(request_access_token_props arg1,  struct svc_req *rqstp)
{
	static request_access_token_res  result;

	if (users[arg1.client_id].authorized == false) {
		result.err = REQUEST_DENIED;
	} else {
		result.err = 0;

		users[arg1.client_id].access_token = generate_access_token(arg1.authorization_token);
		std::cout << "  AccessToken = " << users[arg1.client_id].access_token << std::endl;
		access_tokens[users[arg1.client_id].access_token] = arg1.client_id;

		if (users[arg1.client_id].auto_refresh) {
			users[arg1.client_id].refresh_token = generate_access_token(users[arg1.client_id].access_token);
			std::cout << "  RefreshToken = " << users[arg1.client_id].refresh_token << std::endl;
			refresh_tokens[users[arg1.client_id].refresh_token] = arg1.client_id;
		} else {
			users[arg1.client_id].refresh_token = (char *) "";
		}

		// Store the generated tokens in the result returned to client
		result.request_access_token_res_u.tokens.access_token = users[arg1.client_id].access_token;
		result.request_access_token_res_u.tokens.refresh_token = users[arg1.client_id].refresh_token;
	}

	return &result;
}

refresh_tokens_res *
refresh_tokens_1_svc(refresh_tokens_props arg1,  struct svc_req *rqstp)
{
	static refresh_tokens_res  result;

	if (refresh_tokens.count(arg1.refresh_token) == 0) {
		result.err = INVALID_REFRESH_TOKEN;
		return &result;
	}

	std::string client_id = refresh_tokens[arg1.refresh_token];

	std::cout << "BEGIN " << client_id << " AUTHZ REFRESH" << std::endl;

	// Remove the old access and refresh tokens
	access_tokens.erase(users[client_id].access_token);
	refresh_tokens.erase(users[client_id].refresh_token);

	users[client_id].access_token = generate_access_token(arg1.refresh_token);
	users[client_id].refresh_token = generate_access_token(users[client_id].access_token);
	users[client_id].num_operations = tokens_validity;

	// Update the access token with the client associated
	access_tokens[users[client_id].access_token] = client_id;
	refresh_tokens[users[client_id].refresh_token] = client_id;

	std::cout << "  AccessToken = " << users[client_id].access_token << std::endl;
	std::cout << "  RefreshToken = " << users[client_id].refresh_token << std::endl;

	// Store the refreshed tokens in the result returned to client
	result.refresh_tokens_res_u.tokens.access_token = users[client_id].access_token;
	result.refresh_tokens_res_u.tokens.refresh_token = users[client_id].refresh_token;

	return &result;
}

validate_delegated_action_res *
validate_delegated_action_1_svc(validate_delegated_action_props arg1,  struct svc_req *rqstp)
{
	static validate_delegated_action_res  result;

	// @result is a static variable, so the initialization
	// on declaration will happen only once at the runtime
	result.status = PERMISSION_GRANTED;

	int remaining_operations = 0;
	char *access_token = arg1.access_token;

	if (access_tokens.find(arg1.access_token) == access_tokens.end()) {
		result.status = PERMISSION_DENIED;
	} else {
		std::string user_id = access_tokens[arg1.access_token];

		// Check if there are any remaining operations that can be
		// done using the current access token
		if (users[user_id].num_operations == 0) {
			if (users[user_id].auto_refresh == false) {
				result.status = TOKEN_EXPIRED;

				// Remove the token from the database
				users[user_id].access_token = NULL;
				access_tokens.erase(arg1.access_token);

				access_token = (char *) "";
			} else {
				result.status = REQUIRE_REFRESH;
			}
		} else {
			users[user_id].num_operations -= 1;
			remaining_operations = users[user_id].num_operations;

			if (resources.count(arg1.resource) == 0) {
				result.status = RESOURCE_NOT_FOUND;
			} else {
				std::string permissions_on_resource = users[user_id].permissions[arg1.resource];

				// Check if the client has the permission to performe the
				// requested operation on this specific resource
				if (operation_name.count(arg1.operation) == 0 ||
					permissions_on_resource.find(operation_name[arg1.operation]) == std::string::npos) {
					result.status = OPERATION_NOT_PERMITTED;
				} else {
					result.status = PERMISSION_GRANTED;
				}
			}
		}
	}

	// If the refresh is required, then don't log the status of the
	// current delegated action, since it will be reloaded once the
	// client requests a new pair of <refresh, access> tokens
	if (result.status != REQUIRE_REFRESH) {
		if (result.status != PERMISSION_GRANTED) {
			std::cout << "DENY (";
		} else {
			std::cout << "PERMIT (";
		}

		std::cout << arg1.operation << "," << arg1.resource << ","
			<< access_token << "," << remaining_operations << ")" << std::endl;
	}
	

	return &result;
}
