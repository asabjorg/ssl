/* A UDP echo server with timeouts.
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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <arpa/inet.h>
#include "chat.h"

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/err.h>
/* BIO*/
#include <openssl/bio.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>

/* Hashing */
#include <crypt.h>

/* Defines */
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }
#define ERROR_CHECK_NEG_OR_0(status, msg) if((status <= 0)) { perror(msg); exit(EXIT_FAILURE); }
#define ERROR_CHECK_NEG(status, msg) if((status < 0)) { perror(msg); exit(EXIT_FAILURE); }


/* This variable is 1 while the client is active and becomes 0 after
   a quit command to terminate the client and to clean up the
   connection. */
static int active = 1;


/* To read a password without echoing it to the console.
 *
 * We assume that stdin is not redirected to a pipe and we won't
 * access tty directly. It does not make much sense for this program
 * to redirect input and output.
 *
 * This function is not safe to termination. If the program
 * crashes during getpasswd or gets terminated, then echoing
 * may remain disabled for the shell (that depends on shell,
 * operating system and C library). To restore echoing,
 * type 'reset' into the sell and press enter.
 */
void getpasswd(const char *prompt, char *passwd, size_t size)
{
	struct termios old_flags, new_flags;
	
	/* Clear out the buffer content. */
    memset(passwd, 0, size);
        
    /* Disable echo. */
	tcgetattr(fileno(stdin), &old_flags);
	memcpy(&new_flags, &old_flags, sizeof(old_flags));
	new_flags.c_lflag &= ~ECHO;
	new_flags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSANOW, &new_flags) != 0) {
		perror("tcsetattr");
		exit(EXIT_FAILURE);
	}

	printf("%s", prompt);
	fgets(passwd, size, stdin);

	/* The result in passwd is '\0' terminated and may contain a final
	 * '\n'. If it exists, we remove it.
	 */
	if (passwd[strlen(passwd) - 1] == '\n') {
		passwd[strlen(passwd) - 1] = '\0';
	}

	/* Restore the terminal */
	if (tcsetattr(fileno(stdin), TCSANOW, &old_flags) != 0) {
		perror("tcsetattr");
		exit(EXIT_FAILURE);
	}
}



/* If someone kills the client, it should still clean up the readline
   library, otherwise the terminal is in a inconsistent state. We set
   active to 0 to get out of the loop below. Also note that the select
   call below may return with -1 and errno set to EINTR. Do not exit
   select with this error. */
void
sigint_handler(int signum)
{
        active = 0;
        
        /* We should not use printf inside of signal handlers, this is not
         * considered safe. We may, however, use write() and fsync(). */
        write(STDOUT_FILENO, "Terminated.\n", 12);
        fsync(STDOUT_FILENO);
}


/* The next two variables are used to access the encrypted stream to
 * the server. The socket file descriptor server_fd is provided for
 * select (if needed), while the encrypted communication should use
 * server_ssl and the SSL API of OpenSSL.
 */
static int server_fd;
static SSL *server_ssl;

/* This variable shall point to the name of the user. The initial value
   is NULL. Set this variable to the username once the user managed to be
   authenticated. */
static char *user;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
static char *chatroom;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static char *prompt;

/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */
void readline_callback(char *line)
{
        char buffer[256];
        if (NULL == line) {
                rl_callback_handler_remove();
                active = 0;
                return;
        }
        if (strlen(line) > 0) {
                add_history(line);
        }
        if ((strncmp("/bye", line, 4) == 0) ||
            (strncmp("/quit", line, 5) == 0)) {
				/* Sending command to server */
				memset(buffer, '\0', sizeof(buffer));
        		snprintf(buffer, 255, "%s\n", line);
				SSL_write(server_ssl, buffer, sizeof(buffer));
                rl_callback_handler_remove(); // cleaning up
                active = 0;
                return;
        }
        if (strncmp("/game", line, 5) == 0) {
                /* Skip whitespace */
                printf("Invalid command, no game implemented\n.");/* roll dice and declare winner. */
				fflush(stdout);
                return;
        }
        if (strncmp("/join", line, 5) == 0) {
            int i = 5;
            /* Skip whitespace */
            while (line[i] != '\0' && isspace(line[i])) { i++; }
 	        if (line[i] == '\0') {
                write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
                fsync(STDOUT_FILENO);
                rl_redisplay();
				
                return;
			}

          	char *chatroom = strdup(&(line[i]));

            /* Process and send this information to the server. */

			memset(buffer, '\0', sizeof(buffer));
        	snprintf(buffer, 255, "%s\n", line);
			int x = SSL_write(server_ssl, buffer, sizeof(buffer));
			memset(buffer, '\0', sizeof(buffer));
			x = SSL_read(server_ssl, buffer, sizeof(buffer) - 1);
			buffer[x] = '\0';
			printf("%s",buffer);
			fflush(stdout);
			return;
    	}

        if (strncmp("/list", line, 5) == 0) {

			memset(buffer, '\0', sizeof(buffer));
        	snprintf(buffer, 255, "%s\n", line);
			int x = SSL_write(server_ssl, buffer, sizeof(buffer));
			
			memset(buffer, '\0', sizeof(buffer));
			x = SSL_read(server_ssl, buffer, sizeof(buffer)-1);
			buffer[x] = '\0';
			printf("Available chat rooms: \n%s\n", buffer);
            fflush(stdout);
			return;	
        }

        if (strncmp("/roll", line, 5) == 0) {
                printf("Invalid command, no game implemented\n.");/* roll dice and declare winner. */
				fflush(stdout);
                return;
        }
        if (strncmp("/say", line, 4) == 0) {
                /* Skip whitespace */
                int i = 4;
                while (line[i] != '\0' && isspace(line[i])) { i++; }
                if (line[i] == '\0') {
                        write(STDOUT_FILENO, "Usage: /say username message\n",
                              29);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }
                /* Skip whitespace */
                int j = i+1;
                while (line[j] != '\0' && isgraph(line[j])) { j++; }
                if (line[j] == '\0') {
                        write(STDOUT_FILENO, "Usage: /say username message\n",
                              29);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }

            /* Send private message to receiver. */
        	snprintf(buffer, 255, "%s", line);
			SSL_write(server_ssl, buffer, sizeof(buffer));
			return;
				
        }

        if (strncmp("/user", line, 5) == 0) {
            int i = 5;
            /* Skip whitespace */
            while (line[i] != '\0' && isspace(line[i])) { i++; }
            if (line[i] == '\0') {
            	write(STDOUT_FILENO, "Usage: /user username\n", 22);
                fsync(STDOUT_FILENO);
                rl_redisplay();
                return;
            }

            /* Process and send this information to the server. */
			memset(buffer, '\0', sizeof(buffer));
        	snprintf(buffer, 255, "%s", line);
			SSL_write(server_ssl, buffer, sizeof(buffer));

			/* Get response from server, telling us if this is a new username or not */						
			memset(buffer, '\0', sizeof(buffer));
			int x = SSL_read(server_ssl, buffer, sizeof(buffer)-1);
			buffer[x] = '\0';
			printf("%s\n", buffer);
			fflush(stdout);
			
			char passwd[48];
			
			if(strncmp(&buffer[0], "SIGNUP", 6) == 0){
				char passwd2[48];
				printf("Welcome new user! Please choose a new password.\n");	
				fflush(stdout);
				getpasswd("Password: ", passwd, 48);      
				getpasswd("Retype password: ", passwd2, 48);
				if(strcmp(passwd, passwd2) != 0){
					printf("Passwords did not match, please try again.\n");
					return;
				}
			} 
			else{        
				getpasswd("Password: ", passwd, 48);      
			}
	
			unsigned long int hashed_pass = hash_pass(passwd);
			char password[48];
			memset(password, '\0', sizeof(password));
			snprintf(password, sizeof(password), "%lu", hashed_pass);
			SSL_write(server_ssl, password, sizeof(password));

			return;
        }
  
        if (strncmp("/who", line, 4) == 0) {
            /* Query all available users */
			memset(buffer, '\0', sizeof(buffer));
        	snprintf(buffer, 255, "%s\n", line);
			SSL_write(server_ssl, buffer, sizeof(buffer));
			
			char users[100];
			memset(users, '\0', sizeof(users));
			int x = SSL_read(server_ssl, users, sizeof(users)-1);
			if(x <= 0 ) printf("ERROR receiving !\n");
			users[x] = '\0';
			printf("Online users: \n");
			printf("%s", users);
			fflush(stdout);
			
            return;
        }

        /* Sent the buffer to the server. */
        snprintf(buffer, 255, "%s\n", line);
		int x = SSL_write(server_ssl, buffer, sizeof(buffer));

		memset(buffer, '\0', sizeof(buffer));

}

/* Function to print out custom messages */
void printMsg(char *print){
    fprintf(stdout, "%s\n", print);
    fflush(stdout);
}

int main(int argc, char **argv)
{
	client_startup_check(argc, argv);
	int status = 0, port_n;
	struct sockaddr_in server, client;
	char buffer[4096];
    char *serverIP;

    /* Read server IP address */
    serverIP = malloc(sizeof(&argv[1][0]));
    if(!sscanf(&argv[1][0], "%s", serverIP) || strlen(serverIP) > 15){
        printMsg("Incorrect IP format");
        free(serverIP);
        return 0;
    } 

    /* Read server port number */
    if(!sscanf(&argv[2][0], "%d", &port_n)){
        printMsg("Needs port number.");
        return 0;
    }

	/* Initialize OpenSSL */
	SSL_library_init();	/* Loads encryption and hash algorithms fro SSL */
	SSL_load_error_strings(); /* Loads the error strings for good error reporting */
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_client_method()); /* Creating and setting up ssl context structure*/
        
	/* Setting the certificate */ // TODO is PEM correct?
	status = SSL_CTX_use_certificate_file(ssl_ctx, "client.crt", SSL_FILETYPE_PEM);
	ERROR_CHECK_NEG_OR_0(status, "ERROR: Error Loading certificate filen.\n");
	
	/* Setting the private key */
	status = SSL_CTX_use_PrivateKey_file(ssl_ctx, "client.key", SSL_FILETYPE_PEM);
	ERROR_CHECK_NEG_OR_0(status, "ERROR: Error loading private key file.\n");

	/* Check if certificate and key match */

	status = SSL_CTX_check_private_key(ssl_ctx); 
	ERROR_CHECK_NEG_OR_0(status, "ERROR: Private key does not match the certificate public key.\n");
	
	/* Create the SSL structure */
	server_ssl = SSL_new(ssl_ctx);

	/* Create and set up a listening socket. The sockets you
	 * create here can be used in select calls, so do not forget
	 * them.
	 * TODO is it AF or PF_INET
	 */
	server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ERROR_CHECK_NEG(status, "ERROR: Error creating socket.\n");

	memset (&server, '\0', sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(port_n);       /* Server Port number */
	server.sin_addr.s_addr = inet_addr(serverIP); /* Server IP */

    printf("INFO: Connecting to the server %s:%d \n", serverIP, port_n);
    fflush(stdout);

	/* Establish a TCP/IP connection to the SSL client */
 
	status = connect(server_fd, (struct sockaddr*) &server, sizeof(server));	
	ERROR_CHECK_NEG(status, "ERROR: Error connecting socket.\n");

	/* Use the socket for the SSL connection. */
	SSL_set_fd(server_ssl, server_fd);

    /* Set up secure connection to the chatd server. */
	status = SSL_connect(server_ssl);	
	ERROR_CHECK_NEG_OR_0(status,"ERROR: Error during handshake.\n");
	
	printf ("INFO: SSL connection using %s\n", SSL_get_cipher (server_ssl));
   	
	status = SSL_write(server_ssl, "Hallo.", sizeof("Hallo."));  
	RETURN_SSL(status);
	
	/* Server should say: Welcome. */
	status = SSL_read(server_ssl, buffer, sizeof(buffer)-1);
    buffer[status] = '\0';
	if(strcmp(buffer, "Welcome.\n") != 0){
		printf("ERROR: Error reading welcome message from server.\n");
	}
		
	int max_fd;

	printf("INFO: Server says: %s\n" ,buffer);

	    /* Read characters from the keyboard while waiting for input.
         */
        prompt = strdup("> ");
        rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);

        while (active) {
	    	fd_set rfds;
			struct timeval timeout;

			FD_ZERO(&rfds);
    	    FD_SET(STDIN_FILENO, &rfds);
			FD_SET(server_fd, &rfds);
			max_fd = server_fd;
			timeout.tv_sec = 5;
			timeout.tv_usec = 0;
			if(STDIN_FILENO > server_fd){
            	max_fd = STDIN_FILENO;
       		 }	
            int r = select(max_fd + 1, &rfds, NULL, NULL, &timeout);
            if (r < 0) {
            	if (errno == EINTR) {
                                /* This should either retry the call or
                                   exit the loop, depending on whether we
                                   received a SIGTERM. */
                                continue;
                        }
                        /* Not interrupted, maybe nothing we can do? */
					printf("select\n");
                	perror("select()");
                    break;
			}
    		if (r == 0) {
                fsync(STDOUT_FILENO);
                /* Whenever you print out a message, call this
                         to reprint the current input line. */
				rl_redisplay();
                continue;
           }        
			if (FD_ISSET(STDIN_FILENO, &rfds)) {
            	rl_callback_read_char();
        	}
				
	            /* Check if socket has message */
    	        if(FD_ISSET(server_fd, &rfds)){
        	        memset(buffer, '\0', sizeof(buffer));
            	    /* SSL_read from server since there is a message to read */          
                	int n = SSL_read(server_ssl, buffer, sizeof(buffer)-1);
                	/* If size of message is 0 then the server closed the connection, cleanup. */
                	if(n == 0){
                   	 	printf("INFO: Server unreachable. Exiting.\n");
                   		fflush(stdout);
                    	SSL_shutdown(server_ssl);
                    	close(server_fd);
                    	SSL_free(server_ssl);
                    	SSL_CTX_free(ssl_ctx);
                    	rl_callback_handler_remove();

                    	fsync(STDOUT_FILENO);  
                    	exit(EXIT_SUCCESS);
                	}
                	/* Print the received message on the screen */
                	buffer[n] = '\0';
                	write(STDOUT_FILENO, buffer, strlen(buffer));
					fsync(STDOUT_FILENO);
					rl_redisplay();
        	}
			
	}
	SSL_shutdown(server_ssl);
	close(server_fd);
	SSL_free(server_ssl);
	SSL_CTX_free(ssl_ctx);
  	rl_callback_handler_remove();
   	fsync(STDOUT_FILENO);  
   	exit(EXIT_SUCCESS);
}


