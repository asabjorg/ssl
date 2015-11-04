
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
#include "chat.h"
#include <sys/stat.h>

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

void server_log(const char *msg, struct sockaddr_in * client){
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

    /*
    	althernative way for reading IP address
		int ipAddr = client->sin_addr.s_addr;
		char ip_string[INET_ADDRSTRLEN];
		inet_ntop( AF_INET, &ipAddr, ip_string, INET_ADDRSTRLEN );
    */
    char timestamp[100];
    memset(timestamp, '\0', sizeof(timestamp));
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(timestamp, sizeof(timestamp)-1, "%Y-%m-%dT%H:%M:%S%z", t);

    fprintf(fd, "%s : %s:%d %s\n", timestamp, inet_ntoa(client->sin_addr), ntohs(client->sin_port), msg);
    fclose(fd);
}

long int construct_client_key(struct sockaddr_in * client){
	
	char key[40];
	snprintf(key, 40, "%d%d", client->sin_addr.s_addr, ntohs(client->sin_port));
	long int longint = atol(key);
	printf(" in helpers %ld\n", longint);
	return longint;
}
