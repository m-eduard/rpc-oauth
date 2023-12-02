/* Copyright Eduard Marin, November 2023
 * 
 * ALL THE PROCEDURES HAVE THEIR PARAMETERS STORED IN A DEDICATED
 * STRUCT NAMED AFTER THIS SCHEMA:
 *      <procedure_name>_props
 * AND THE RESULT OF THE PROCEDURE IS SEND OVER NETWORK USING A
 * UNION NAMED:
 *      <procedure_name>_res
 */

/* Typedefs added in order to easily change what they store based on
 * further requirements, without modifying the already existing structs */
typedef string client_id_t<15>;
typedef string token_t<>;
typedef string operation_t<>;
typedef string resource_t<>;

/* Struct containing both the access and refresh tokens */
struct bearer_tokens_t {
    token_t access_token;
    token_t refresh_token;
};


/* REQUEST_AUTHORIZATION receives only a client ID and auto refresh value */
struct request_authorization_props {
    client_id_t client_id;
    bool auto_refresh;
};

/* REQUEST_AUTHORIZATION returns an auth token if the user who requested the
 * the token exists in the Users DB on the server side */
union request_authorization_res switch (int err) {
	case 0:
		token_t token;      /* no error: return the authorization token */
	default:
		void;			    /* error occurred: nothing else to return */
};


/* APPROVE_REQUEST_TOKEN receives an authorization token which is either signed
 * (associated with a couple of permissions), or rejected by the final user */
struct approve_request_token_props {
    token_t authorization_token;
};

/* APPROVE_REQUEST_TOKEN returns a boolean which shows if the requested
 * permissions were granted or not by the final user for the current
 * authorization request token */
struct approve_request_token_res {
    bool was_signed;
};


/* REQUEST_ACCESS_TOKEN receives a client ID and an authorization token */
struct request_access_token_props {
    client_id_t client_id;
    token_t authorization_token;
};

/* REQUEST_ACCESS_TOKEN returns an access token and a refresh token if the
 * received authorization token is signed, otherwise an error */
union request_access_token_res switch (int err) {
    case 0:
        bearer_tokens_t tokens;
    default:
        void;
};


/* REFRESH_TOKENS receives a refresh token to regenerate the tokens
 * (the client identity will also be determined based on this token) */
struct refresh_tokens_props {
    token_t refresh_token;
};

/* REFRESH_TOKENS returns a new access token and a new refresh token
 * if the received refresh token is valid, otherwise an error */
union refresh_tokens_res switch (int err) {
    case 0:
        bearer_tokens_t tokens;
    default:
        void;
};


/* VALIDATE_DELEGATED_ACTION receives the resource, the operation
 * that has to be performed and an access token */
struct validate_delegated_action_props {
    operation_t operation;
    resource_t resource;
    token_t access_token;
};

/* VALIDATE_DELEGATED_ACTION returns just an error code, which is then checked
 * on the client side in order to see if the operation was successful or not */
struct validate_delegated_action_res {
    int status;
};

program OAUTH_PROG {
    version OAUTH_VERS {
        request_authorization_res REQUEST_AUTHORIZATION(request_authorization_props) = 1;
        approve_request_token_res APPROVE_REQUEST_TOKEN(approve_request_token_props) = 2;
        request_access_token_res REQUEST_ACCESS_TOKEN(request_access_token_props) = 3;
        refresh_tokens_res REFRESH_TOKENS(refresh_tokens_props) = 4;
        validate_delegated_action_res VALIDATE_DELEGATED_ACTION(validate_delegated_action_props) = 5;
    } = 1;
} = 0x31234567;
