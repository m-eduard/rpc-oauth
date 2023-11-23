#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <string>
#include <unordered_map>

#define MACRO_RAW(x) #x

std::unordered_map<std::string, std::string> operation_name = {
	{"READ", "R"},
	{"INSERT", "I"},
	{"MODIFY", "M"},
	{"DELETE", "D"},
	{"EXECUTE", "X"},
};

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
