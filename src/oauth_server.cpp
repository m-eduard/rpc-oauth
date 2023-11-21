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
std::unordered_set<std::string> users;
std::unordered_set<std::string> resources;
std::vector<std::unordered_map<std::string, std::string>> approvals;
int tokens_validity;

void server_init(server_init_props *props) {
	std::vector<std::string> clients_lines;
	get_lines_from_file(props->clients_file, true, clients_lines);

	for (int i = 0; i < clients_lines.size(); ++i) {
		users.insert(clients_lines[i]);
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

	tokens_validity = props->tokens_validity;
}


request_authorization_res *
request_authorization_1_svc(request_authorization_props arg1,  struct svc_req *rqstp)
{
	static request_authorization_res result;

	if (users.find(arg1.client_id) == users.end()) {
		result.err = USER_NOT_FOUND;
	} else {
		result.err = 0;
		result.request_authorization_res_u.token = generate_access_token(arg1.client_id);
	}

	return &result;
}

approve_request_token_res *
approve_request_token_1_svc(approve_request_token_props arg1,  struct svc_req *rqstp)
{
	static approve_request_token_res  result;

	/*
	 * insert server code here
	 */

	return &result;
}

request_access_token_res *
request_access_token_1_svc(request_access_token_props arg1,  struct svc_req *rqstp)
{
	static request_access_token_res  result;

	/*
	 * insert server code here
	 */

	return &result;
}

refresh_tokens_res *
refresh_tokens_1_svc(refresh_tokens_props arg1,  struct svc_req *rqstp)
{
	static refresh_tokens_res  result;

	/*
	 * insert server code here
	 */

	return &result;
}

validate_delegated_action_res *
validate_delegated_action_1_svc(validate_delegated_action_res arg1,  struct svc_req *rqstp)
{
	static validate_delegated_action_res  result;

	/*
	 * insert server code here
	 */

	return &result;
}
