#include <string>

/* struct containing:
 *	- id of the user performing the action
 *  - action which is executed
 *  - resource on which the action is executed / automatic refresh value
 *    if the action type is REQUEST
 */
struct operation_props {
    std::string user_id;
    std::string action;
    union {
        char *resource;
        bool automatic_refresh;
    };
};

#define READ    "READ"
#define INSERT  "INSERT"
#define MODIFY  "MODIFY"
#define DELETE  "DELETE"
#define EXECUTE "EXECUTE"

#define REQUEST "REQUEST"

/* Usually, the server should run on a machine, and the client
 * on another machine, so using a common .h file to store the
 * values for these error macros would not work unless both
 * are compiled on the same machine */
#define USER_NOT_FOUND 1
#define REQUEST_DENIED 2
#define PERMISSION_DENIED 3
#define TOKEN_EXPIRED 4
#define RESOURCE_NOT_FOUND 5
#define OPERATION_NOT_PERMITTED 6
#define PERMISSION_GRANTED 7
