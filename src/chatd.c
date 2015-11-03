/* A TCP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <glib.h>

#include "chat.h"


/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Defines */
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }
#define ERROR_CHECK_NEG_OR_0(status, msg) if((status <= 0)) { perror(msg); exit(EXIT_FAILURE); }
#define ERROR_CHECK_NEG(status, msg) if((status < 0)) { perror(msg); exit(EXIT_FAILURE); }
#define ERROR_CHECK_NOT(status, msg) if(!status) { perror(msg); }
#define ERROR_CHECK_NOT_NULL(status, msg) if((status == NULL)) { perror(msg); }


GTree * clients;
const char * chat_rooms[3];


/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
        const struct sockaddr_in *_addr1 = addr1;
        const struct sockaddr_in *_addr2 = addr2;

        /* If either of the pointers is NULL or the addresses
           belong to different families, we abort. */
		g_assert((_addr1 != NULL) && (_addr2 != NULL) &&
		(_addr1->sin_family == _addr2->sin_family));

        if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
                return -1;
        } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
                return 1;
        } else if (_addr1->sin_port < _addr2->sin_port) {
                return -1;
        } else if (_addr1->sin_port > _addr2->sin_port) {
                return 1;
        }
        return 0;
}

gboolean listen_for_messages(gpointer key, gpointer value, gpointer fd_set_par){

	struct user * le_user = value;
	struct sockaddr_in address = le_user->client;
	SSL * ssl = le_user->ssl;
	int fd = le_user->fd;
	int status = 0;	

	if (FD_ISSET(fd, (fd_set *)fd_set_par)){
		char msg[1024];
		status = SSL_read(ssl, msg, sizeof(msg) - 1);
		ERROR_CHECK_NEG_OR_0(status, "ERROR: Error reading in listen_for_messages\n");
		msg[status] = '\0';
		printf("User:%d says: %s\n", ntohs(address.sin_port), msg);
	}

	return FALSE;	
}

void handle_request(char * buffer, SSL * ssl){
	int status = 0;
	
		
	if(strncmp("/list", buffer, 5) == 0){
		char rooms[100];
		memset(rooms, '\0', sizeof(rooms));
		for(int i = 0; i < 3; i++){
			strcat(rooms, chat_rooms[i]);
			strcat(rooms, "\n");
		}
		strcat(rooms, "\0");
		printf("rooms %s\n", rooms);
		status = SSL_write(ssl, rooms, sizeof(rooms));
		ERROR_CHECK_NEG_OR_0(status, "ERROR: Error in sending chat rooms.\n");
	}
	
	
}


int main(int argc, char **argv)
{
	/* Checks if parameters are available and valid */
	server_startup_check(argc, argv);
	int opt = TRUE;
	int master_socket;
	int status = 0;
	int sock;
	int listen_socket;
	struct sockaddr_in server, client;
    char buffer[4096];
	SSL * server_ssld;
	SSL_CTX * ssl_ctx;

	
	chat_rooms[0] = "Iceland";
	chat_rooms[1] = "Lithuania";
	chat_rooms[2] = "Germany";
	
	
	/* Initilize a client tree */
	clients = g_tree_new(sockaddr_in_cmp);

	/* Load encryption and hasing algortihms, and error strings */
	SSL_library_init();
	SSL_load_error_strings();

	/* Creating a SSL_CTX structure*/
	ssl_ctx = SSL_CTX_new(TLSv1_method());
	if(!ssl_ctx){
		printf("ERROR: Error creating context.\n");
		exit(EXIT_FAILURE);
	}

	/* Loading server certificate */
	status = SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM);
	ERROR_CHECK_NEG_OR_0(status, "ERROR: Error loding server certificate.\n");
	
	/* Loading server privte key*/
	status = SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM);
	ERROR_CHECK_NEG_OR_0(status, "ERROR: Error loding server private key.\n");
	
	/* Making sure certificate and private key match*/
	status = SSL_CTX_check_private_key(ssl_ctx);
	ERROR_CHECK_NEG_OR_0(status, "ERROR: Error matching private key.\n");

    /* Create and bind a TCP socket */
	master_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ERROR_CHECK_NEG(status, "ERROR: Error creating listen socket.\n");

	if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0 )
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

	memset(&server, '\0', sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(atoi(argv[1]));
    
	/* Binding socket to port */    
	status = bind(master_socket, (struct sockaddr *) &server, (socklen_t) sizeof(server));
	ERROR_CHECK_NEG(status, "ERROR: Could not bind to port.\n");

	 /* Listen to port */
	status = listen(master_socket, MAX_USERS);
	ERROR_CHECK_NEG(status, "ERROR: Error while listening to listen_socket.\n");

	 //accept the incoming connection
	int addrlen = sizeof(client);
	printf("Waiting for connections ...\n");

	int max_sd, sd, new_socket, valread, activity;
	fd_set rfds;
	int client_sockets[MAX_USERS];	
	SSL * ssls[MAX_USERS];
	for(int i = 0 ; i < MAX_USERS; i++ ){client_sockets[i] = 0; ssls[i]=NULL;}
	
	while(TRUE){
        struct timeval tv;
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
        int retval;
		FD_SET(master_socket, &rfds);
		max_sd = master_socket;
	
		//add child sockets to set
		for ( int i = 0 ; i < MAX_USERS ; i++){
			//socket descriptor
			sd = client_sockets[i];
			if(sd > 0){
                FD_SET( sd , &rfds);
			}

			//highest file descriptor number, need it for the select function
            if(sd > max_sd){
			     max_sd = sd;
			}
		}

		//wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
		activity = select( max_sd + 1 , &rfds , NULL , NULL , &tv);
		if ((activity < 0) && (errno!=EINTR)) 
        {
            printf("select error");
        }
		if (FD_ISSET(master_socket, &rfds)) 
        {


            if ((new_socket = accept(master_socket, (struct sockaddr *)&client, (socklen_t*)&client))<0)
            {
                perror("accept");
                exit(EXIT_FAILURE);
            }
          
            //inform user of socket number - used in send and receive commands
////		            printf("New connection , socket fd is %d , ip is : %s , port : %d \n" , new_socket , inet_ntoa(client.sin_addr) , ntohs(client.sin_port));
        		
			// SSL SHIT
			SSL * newssl = SSL_new(ssl_ctx);
			SSL_set_fd(newssl, new_socket);
			SSL_accept(newssl);
				
            //send new connection greeting message
            status = SSL_write(newssl, "Welcome.\n", sizeof("Welcome.\n"));
              
            printf("Welcome message sent with status %d\n", status);
			 
			int xx = SSL_read(newssl, buffer, sizeof(buffer)-1);
		
			buffer[xx] = '\0';
			printf("--- %s\n", buffer);

 
            //add new socket to array of sockets
            for (int i = 0; i < MAX_USERS; i++) 
            {
                //if position is empty
                if( client_sockets[i] == 0 )
                {
                    client_sockets[i] = new_socket;
					ssls[i] = newssl;
                    printf("Adding to list of sockets as %d\n" , i);
                     
                    break;
                }
            }
        }//endof if fd isset

		//else its some IO operation on some other socket :)
		for (int i = 0; i < MAX_USERS; i++) 
        {
			sd = client_sockets[i];
			SSL * currSSL = ssls[i];
			if (FD_ISSET( sd , &rfds)) 
            {

			//Check if it was for closing , and also read the incoming message
				if ((valread = SSL_read(currSSL, buffer, sizeof(buffer)-1)) == 0)
                {//Somebody disconnected , get his details and print
					printf("Host disconnected , ip %s , port %d \n" , inet_ntoa(client.sin_addr) , ntohs(client.sin_port));
					//Close the socket and mark as 0 in list for reuse
					close( sd );
			        client_sockets[i] = 0;
					ssls[i] = NULL;
				}
				else{
					buffer[valread] = '\0';
                    //send(sd , buffer , strlen(buffer) , 0 );
                    printf("--read: %s\n", buffer);
					handle_request(&buffer[0], currSSL);
				}
			}
		}

	}// END OF WHILE LOOP
}
