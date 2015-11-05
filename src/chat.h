#include <glib.h>
#include <openssl/ssl.h>

struct user{
	int fd;
	SSL *ssl;
	struct sockaddr_in client;

};

struct authentication{
	char * username;
	char * password;
};

#define MAX_USERS 1024

void server_startup_check(int argc, char * argv[]);

void client_startup_check(int argc, char * argv[]);

void handle_request(char * buffer, SSL * ssl, struct user * the_user);

void server_log(const char *msg, struct sockaddr_in * client, char * username);

unsigned long hash_pass(char *str);
