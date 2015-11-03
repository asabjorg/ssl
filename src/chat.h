#include <glib.h>

#include <openssl/ssl.h>

void server_startup_check(int argc, char * argv[]);

void client_startup_check(int argc, char * argv[]);

void log(const char *msg, struct sockaddr_in * client);

long int construct_client_key(struct sockaddr_in * client);

gboolean listen_for_messages(gpointer key, gpointer value, gpointer fd_set_par);

/* TODO keep an eye on this !*/
/*typedef struct{
	
	char* username;
	char* ip;
	int port;
	char* password; // or char [24], depend on hashing
} User;
*/
struct user{

	int fd;
	SSL *ssl;
	struct sockaddr_in client;

};

#define MAX_USERS 1024
