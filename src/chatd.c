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
#include <arpa/inet.h>
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

struct user * all_users[MAX_USERS];
int client_sockets[MAX_USERS];	
SSL * ssls[MAX_USERS];
char * usernames[MAX_USERS];


const char * chat_rooms[3];
struct user * users_iceland[MAX_USERS];
struct user * users_lithuania[MAX_USERS];
struct user * users_germany[MAX_USERS];

/*
 * This method takes care of handling requests according
		 * to their prefix
		 * */
		void handle_request(char * buffer, SSL * ssl, struct user * the_user){
			int status = 0;
			int fd = the_user->fd;
			
			if(strncmp("/list", buffer, 5) == 0){
				char rooms[100];
				memset(rooms, '\0', sizeof(rooms));
				for(int i = 0; i < 3; i++){
					strcat(rooms, chat_rooms[i]);
					strcat(rooms, "\n");
				}
				strcat(rooms, "\0");
				status = SSL_write(ssl, rooms, sizeof(rooms));
				ERROR_CHECK_NEG_OR_0(status, "ERROR: Error in sending chat rooms.\n");
			}// ENFOF IF LIST

			else if(strncmp("/who", buffer, 4) == 0){
				char users[1000];
				memset(users, '\0', sizeof(users));
				for(int i = 0; i < MAX_USERS; i++){
					if(all_users[i] != NULL){
						char * usern = usernames[fd];
						strcat(users, usern);
						strcat(users, "\n");
					}
				}
				strcat(users, "\0");
				int n = SSL_write(the_user->ssl, users, sizeof(users));
				if(n <= 0) printf("ERROR SENDING\n");


			}//ENDOF IF WHO

			else if(strncmp("/say", buffer, 4) == 0){
				char * privmsg = NULL;
				int b = 0;

				for(unsigned int i = 0; i < strlen(buffer); i++){
					if(buffer[i] == ' '){
						b++;
					}
					if(b == 2){
						privmsg = &buffer[i+1];
						break;
					}
				}
				char * to = strtok(buffer, " \r\n");
				to = strtok(NULL, " \r\n");
				
				for(int i = 0; i < MAX_USERS; i++){
					if(all_users[i] != NULL){
						if(strcmp(usernames[i], to) == 0){
							SSL_write(all_users[i]->ssl, privmsg, sizeof(privmsg));
						}
					}
				}
			}

			else if(strncmp("/user", buffer, 5) == 0){
				//all_users[fd]->username = &buffer[6];
				char * tempusername = strtok(buffer, " \r\n");
				tempusername = strtok(NULL, " \r\n");
				usernames[fd] = tempusername;
				SSL_write(the_user->ssl, "Your username has been changed.\n", 
					sizeof("Your username has been changed.\n"));
			}//ENDOF IF USER

			else if(strncmp("/join", buffer, 5) == 0){
				char * room = strtok(buffer, " \r\n");
				room = strtok(NULL, " \r\n");
				if(strcmp(room, "Iceland") == 0){
					/* Add to chat room and make sure the user leaves other chat rooms*/	
				int index = the_user->fd;
				users_lithuania[index] = NULL;
				users_germany[index] = NULL;
				users_iceland[index] = the_user;
				SSL_write(the_user->ssl, "Welcome to Iceland!\n", sizeof("Welcome to Iceland!\n"));
				}	
		 	
			else if(strcmp(room, "Lithuania") == 0){
				/* Add to chat room and make sure the user leaves other chat rooms*/	
        		int index = the_user->fd;
				users_iceland[index] = NULL;
				users_germany[index] = NULL;
            	users_lithuania[index] = the_user;
				SSL_write(the_user->ssl, "Welcome to Lithuania!\n", sizeof("Welcome to Iceland!\n"));
        	}
			else if(strcmp(room, "Germany") == 0){
				/* Add to chat room and make sure the user leaves other chat rooms*/	
				int index = the_user->fd;
				users_iceland[index] = NULL;
				users_lithuania[index] = NULL;
				users_germany[index] = the_user;
				SSL_write(the_user->ssl, "Welcome to Germany!\n", sizeof("Welcome to Iceland!\n"));
    		}
			else{
				printf("WARNING: Invalid chatroom\n");
		}
		for(int i = 0; i < 1024; i++){
			/* List users in chat rooms*/
			if(users_iceland[i] != NULL) printf("User %d is in room Iceland\n", users_iceland[i]->fd);
			if(users_lithuania[i] != NULL) printf("User %d is in room Lithuania\n", users_lithuania[i]->fd);
			if(users_germany[i] != NULL) printf("User %d is in room Germany\n", users_germany[i]->fd);
		}
			
	}// ENDOF IF JOIN	

	/* If we get here it means there was no command, just a chat message*/
	else{

		char temp[sizeof(buffer) + sizeof(usernames[fd]) + 7];
		memset(temp, '\0', sizeof(temp));
		strcpy(temp, usernames[fd]);
		strcat(temp, " says: ");
		strcat(temp, buffer);
		for(int i = 0; i < MAX_USERS; i++){
			if(all_users[i] != NULL){
				if(i != fd){
					if((users_iceland[i] != NULL && users_iceland[fd] != NULL) \
						|| (users_lithuania[i] != NULL && users_lithuania[fd] != NULL) \
						|| (users_germany[i] != NULL && users_germany[fd] != NULL))
						{
							SSL_write(all_users[i]->ssl, temp, sizeof(temp));
						}
				}
			}
		}
	}

}// ENDOF handle_request

/*
 * A simple helper function to initialize some data
*/
void initialize(){
	for(int i = 0 ; i < MAX_USERS; i++ ){
    	client_sockets[i] = 0;
        ssls[i] = NULL;
        users_iceland[i] = NULL;
        users_lithuania[i] = NULL;
        users_germany[i] = NULL;
		all_users[i] = NULL;
		usernames[i] = 	NULL;
    }

    chat_rooms[0] = "Iceland";
    chat_rooms[1] = "Lithuania";
    chat_rooms[2] = "Germany";
	
}

int main(int argc, char **argv)
{
	/* Checks if parameters are available and valid */
	server_startup_check(argc, argv);
	
	int status = 0, opt = TRUE, master_socket, max_sd, sd, new_socket, valread, activity;
	struct sockaddr_in server, client;
    char buffer[4096];
	SSL_CTX * ssl_ctx;
	fd_set rfds;

	/* Calling a helper function to initialize some variables */
	initialize();	

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

	if(setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)
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

	printf("Server is ready and waiting for connections.\n");
	
	while(TRUE){
        struct timeval tv;
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(master_socket, &rfds);
		max_sd = master_socket;
	
		/* add child sockets to set */
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
            printf("ERROR: select error\n");
        }
		else if (activity > 0 && FD_ISSET(master_socket, &rfds)){

			socklen_t len;
			len = (socklen_t) sizeof(client);

            new_socket = accept(master_socket, (struct sockaddr *)&client, &len);
			ERROR_CHECK_NEG(new_socket, "ERROR: Error during accept.\n");

			server_log("connected", &client);
	
			/* SSL connection initialization */
			SSL * newssl = SSL_new(ssl_ctx);
			SSL_set_fd(newssl, new_socket);
			SSL_accept(newssl);
				
            /* Send a welcome message to our new client. */
            status = SSL_write(newssl, "Welcome.\n", sizeof("Welcome.\n"));
			ERROR_CHECK_NEG_OR_0(status, "ERROR: Error during welcome messge to new client.\n");              

			int n = SSL_read(newssl, buffer, sizeof(buffer)-1);
		
			buffer[n] = '\0';

            /* Add the new client socket and ssl to our array */
            for (int i = 0; i < MAX_USERS; i++) 
            {
                //if position is empty
                if( client_sockets[i] == 0 )
                {
                    client_sockets[i] = new_socket;
					ssls[i] = newssl;
                    break;
                }
            }

			/* Setting user info */
			struct user * new_user = malloc(sizeof(struct user));
			new_user->fd = new_socket;
			new_user->ssl = newssl;
			new_user->client = client;
			usernames[new_socket] = "anonymous";
			all_users[new_socket] = new_user;
			
        }//endof if fd isset

		/* Else it is a message from a previous client (not new) */
		for (int i = 0; i < MAX_USERS; i++) 
        {
			sd = client_sockets[i];
			SSL * currSSL = ssls[i];
			if (FD_ISSET( sd , &rfds)) 
            {
			//Check if it was for closing , and also read the incoming message
				if ((valread = SSL_read(currSSL, buffer, sizeof(buffer)-1)) == 0)
                {
					buffer[valread] = '\0';
					/* The client has disconnected */
					server_log("disconnected", &client);

					/* Close the connection and clear all user data*/
					close( sd );
			        client_sockets[i] = 0;
					ssls[i] = NULL;
					all_users[sd] = NULL;
					users_iceland[sd] = NULL;
					users_lithuania[sd] = NULL;
					users_germany[sd] = NULL;

				}
				else{
					buffer[valread] = '\0';
                    //send(sd , buffer , strlen(buffer) , 0 );
					struct user * the_user = all_users[sd];
					if(the_user == NULL) {
						printf("ERROR: User not found\n");
						break;
					}
					
			        if(strncmp("/bye", buffer, 4) == 0){
    	        	    /* Close the connection and reset all user data*/
						server_log("disconnected", &(all_users[sd]->client));
						printf("%s has left the chat.\n", usernames[sd]);
						close(sd);
	        	        client_sockets[i] = 0;
						ssls[i]= NULL;
						all_users[sd] = NULL;
						users_iceland[sd] = NULL;
						users_germany[sd] = NULL;
						users_lithuania[sd] = NULL;
						
					}		
					else{
						handle_request(&buffer[0], currSSL, the_user);
					}
				}
			}
		}

	}// END OF WHILE LOOP
}
