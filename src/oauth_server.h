/* struct containing:
 *	- name of all the files needed to initialize the databases
 *  - number of operations that a token can be used until it becomes invalid
 */
typedef struct server_init_props {
    char *clients_file;
    char *resources_file;
    char *permissions_file;
    int tokens_validity;
} server_init_props;

/* @param props: pointer to the files needed for initializing the DBes
 * 				 stored by the Authentication server*/
void server_init(server_init_props *);