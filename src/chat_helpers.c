
#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include "chat.h"

/* A helper function to check if the port number is
 * missing or invalid*/
void server_startup_check(int argc, char * argv[]){
	if(argc < 2){
		printf("ERROR: Port number missing\n");
		exit(EXIT_FAILURE);
	}

	int port_number = atoi(argv[1]);
	if(port_number < 0 || port_number > 65535){
                printf("ERROR: The port number is invalid, please try again.\n");
                exit(EXIT_FAILURE);
	}
}

/* A helper function to check if address and port number
 * are missing or invalid */
void client_startup_check(int argc, char * argv[]){
	if(argc < 3){
		printf("ERROR: Too few arguments, address and/or port number missing.\n");
		exit(EXIT_FAILURE);
	}

	int port_number = atoi(argv[2]);
	if(port_number < 0 || port_number > 65535){
                printf("ERROR: The port number is invalid, please try again.\n");
		exit(EXIT_FAILURE);
	}	
}

void log(const char *msg, struct sockaddr_in * client){
	FILE *f = fopen("server.log", "a");
	if (f == NULL)
	{	
    	printf("Error opening file!\n");
    	exit(EXIT_FAILURE);
	}

	int ipAddr = client->sin_addr.s_addr;
	char ip_string[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &ipAddr, ip_string, INET_ADDRSTRLEN );
	
	fprintf(f, "%s %s : %s:%d %s\n", __DATE__, __TIME__, ip_string, ntohs(client->sin_port), msg);

	fclose(f);
}

long int construct_client_key(struct sockaddr_in * client){
	
	char key[40];
	snprintf(key, 40, "%d%d", client->sin_addr.s_addr, ntohs(client->sin_port));
	long int longint = atol(key);

	return longint;
}
