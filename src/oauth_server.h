/* struct containing:
 *	- name of all the files needed to initialize the databases
 *  - number of operations that a token can be used until it becomes invalid
 */
#include <string>
#include <unordered_map>

struct server_init_props {
    char *clients_file;
    char *resources_file;
    char *permissions_file;
    int tokens_validity;
};

struct user_data {
    token_t authorization_token;
    token_t access_token;
    token_t refresh_token;
    int num_operations;
    bool auto_refresh;
    bool authorized;
    std::unordered_map<std::string, std::string> permissions;
};

/* @param props: pointer to the files needed for initializing the DBes
 * 				 stored by the Authentication server*/
void server_init(server_init_props *);

#define ALL                 "*"
#define DENY_PERMISSION     "-"

#define USER_NOT_FOUND 1
#define REQUEST_DENIED 2
#define PERMISSION_DENIED 3
#define TOKEN_EXPIRED 4
#define RESOURCE_NOT_FOUND 5
#define OPERATION_NOT_PERMITTED 6
#define PERMISSION_GRANTED 7
