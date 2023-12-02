Oauth with RPC
====================

### by Marin Eduard-Constantin
November 2023

## Flow
1. Operations are read on the Client side, and then for each operation the coresponding RPC procedure is called.
2. The RPC procedure will call the coresponding function on the Server side, which will return a response to the client.
3. Server side procedures:
    - `request_authorization`:
        - server checks if the received user_id exists in the database of users
        - user_id exists => generate an auth token and associates the user with a couple of information regarding different features (authorization token, auto refresh, remaining operations) | also associates the token with the user_id, for efficient further lookup for the user_id using this token
        - otherwise => return `USER_NOT_FOUND`
    - `approve_request_token`:
        - lookup by the auth token received, to find the client_id
        - associate the user_id with the permissions read from approvals file
        - if the permissions are not `*,-`, mark the current token as signed in the hashmap of `users -> users data`
        - increment the index of the current position in the approvals array
    - `request_access_token`:
        - check if the client requesting this operation has the authorization token signed
        - if it does => generate an access token and a refresh token, if refresh option is activated for the current user
        - otherwise => return `REQUEST_DENIED`
    - `validate_delegated_action`:
        - check if the received access token is valid (meaning associated with a user):
            - if it is => check if the number of operations that can be done by the user with this token is > 0:
                - if it is => decrement the number of operations that can be done by the user with this token
                - otherwise => return `TOKEN_EXPIRED`, if the user does not have the option of auto refresh enabled, or `REQUIRE_REFRESH` if it is enabled (`REQUIRE_REFRESH` will trigger the client to call the `refresh_tokens` procedure, and then retry the current operation)
            - otherwise, return `PERMISSION_DENIED`
        - if all the checks have passed, further check if the received resource name is valid:
            - if it is => check if the received action is valid and allowed for the received resource:
                - if it is => return `PERMISSION_GRANTED`
                - otherwise => return `OPERATION_NOT_PERMITTED`
            - otherwise => return `RESOURCE_NOT_FOUND`
    - `refresh_tokens`:
        - check if there is any user associated with the received refresh token
        - if there is, generate a new access token and refresh token based on the received token

4. The result is parsed and displayed on the Client side.


<b>`OBS!`</b>

If the client receives `REQUIRE_REFRESH` as a response from `validate_delegated_action`, the logic of refreshing the tokens is implemented in server, but it will be triggered by the client, by calling the `refresh_tokens` procedure.

This decision was made because sometimes the client might want to refresh its tokens, even if they are not expired, and if we are hidding this feature of refreshing the tokens and just implementing it in the server as a simple function, then the tokens will be refreshed only automatically, and this process will be completely hidden from the client.


## Implementation

### Interface
All of the RPC procedures return either an error code, or a struct containing the useful data regarding the call, if it was successful (read oauth.x for more details).

### Databases Initialization
When the OAuth Server is started, all the files about clients, resources name and permissions are read using a generic function, parsed and loaded into memory. To store them, a couple of global unordered_maps, vectors and unordered_sets are used.

To store them directly in the oauth_server.cpp file, without using the `extern` keyword for global variables, a `server_init()` function is defined in oauth_server.h, which is called in the `main()` function of oauth_svc.c, but implemented in oauth_server.cpp.

Approvals are stored in an array, and using a global variable as an index, the next approval is used in a FIFO style in order to associate the permissions with the access token requested by the client. Permissions are stored as a hashmap with the name of the resource mapped to a string, and using a map each letter is associated with a different permission:
- "R" - "READ"
- "I" - "INSERT"
- "M" - "MODIFY"
- "D" - "DELETE"
- "X" - "EXECUTE"

## Stubs Changes
The server stub (oauth_svc.c) was updated to call a server init function (located in oauth_server.cpp), which populates the databases based on the data found in the files provided as command line arguments when the server is started.

Also, all register specifiers are removed from svc and xdr stubs (oauth_svc.cpp and oauth_xdr.cpp)

In the makefile, g++ is configured as CC, in order to avoid getting a linkage error (gcc cannot link object files obtained from C++ source files).
