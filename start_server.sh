CLIENTS_FILE=""
RESOURCES_FILE=""
PERMISSIONS_FILE=""
TOKENS_VALIDITY=0

# ./oauth_server tests/test11/userIDs.db tests/test1/resources.db tests/test1/approvals.db 4
./server "$CLIENTS_FILE" "$RESOURCES_FILE" "$PERMISSIONS_FILE" "$TOKENS_VALIDITY"