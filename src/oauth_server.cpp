#include "oauth.h"
#include "oauth_server.h"
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

void get_lines_from_file(char *file, bool has_num_lines, std::vector<std::string> &lines) {
	char buffer[1024] = {0};
	int num_lines = 0;
	int buffer_pos = 0;

	int fd = open(file, O_RDONLY);
	if (fd < 0) {
		printf("Error opening %s\n", file);
	}

	read(fd, buffer, 1024);

	if (has_num_lines) {
		num_lines = atoi(buffer);
		buffer_pos = strchr(buffer, '\n') - buffer + 1;
	}

	do {
		for (int i = buffer_pos; i < sizeof(buffer); ++i) {
			if (buffer[i] == '\n') {
				lines.push_back(std::string(buffer + buffer_pos, i - buffer_pos));

				if (has_num_lines) num_lines--;

				buffer_pos = i + 1;
			}
		}

		// Check if the file ended without '\n'
		if (has_num_lines) {
			if (num_lines > 0)
				lines.push_back(std::string(buffer + buffer_pos));
		} else {
			if (buffer_pos < sizeof(buffer))
				lines.push_back(std::string(buffer + buffer_pos));
		}

		buffer_pos = 0;
	} while (read(fd, buffer, 1024) > 0);
}

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
}


request_authorization_res *
request_authorization_1_svc(request_authorization_props arg1,  struct svc_req *rqstp)
{
	static request_authorization_res  result;

	/*
	 * insert server code here
	 */

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
