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
#include <arpa/inet.h>
#include <sys/stat.h>
#include <crypt.h>


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
/* A helper function for logging */
void server_log(const char *msg, struct sockaddr_in * client, char * username){
	FILE *fd;
    struct stat st = {0};

    /* if folder does not exists, make folder! */
    if (stat("logs", &st) == -1) {
        mkdir("logs", 0700);
    }

    if((fd = fopen("logs/server.log", "a")) == NULL){
        perror("open()");
        exit(EXIT_FAILURE);
    }

    char timestamp[100];
    memset(timestamp, '\0', sizeof(timestamp));
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(timestamp, sizeof(timestamp)-1, "%Y-%m-%dT%H:%M:%S%z", t);

	if(username == NULL){
	    fprintf(fd, "%s : %s:%d %s\n", timestamp, inet_ntoa(client->sin_addr), ntohs(client->sin_port), msg);
	}
	else{
	    fprintf(fd, "%s : %s:%d %s %s\n", timestamp, inet_ntoa(client->sin_addr), ntohs(client->sin_port), username, msg);
	}
    fclose(fd);
}

/* 
 * Hash function.
 * REFERENCE: http://www.cse.yorku.ca/~oz/hash.html 
 */
unsigned long hash_pass(char *str){
	unsigned long hash = 5381;
    int c;

    while((c = *str++)){
        hash = ((hash << 5) + hash) + c;
	}

   	return hash;
}
