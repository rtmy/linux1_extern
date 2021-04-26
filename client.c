#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#define BUF_LEN 1024


int talk(char *message, char *ip, int port) {
    int sockfd = 0, n = 0;
    char recvBuff[BUF_LEN];
    struct sockaddr_in serv_addr;

    memset(recvBuff, '0',sizeof(recvBuff));
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    }

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if(inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    }

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("\n Error : Connect Failed \n");
       return 1;
    }

    printf("buff %s %d\n", message, strlen(message));

    n = write(sockfd, message, strlen(message)*sizeof(char));

    while ( (n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0)
    {
            recvBuff[n] = 0;
            if(fputs(recvBuff, stdout) == EOF)
            {
                printf("\n Error : Fputs error\n");
            }
    	printf("\n");
    }

    if(n < 0)
    {
        printf("\n Read error \n");
    }

    return 0;
}


int main(int argc, char *argv[]) {

    if(argc < 3) {
        printf("Usage: %s <ip of server> <port>\n", argv[0]);
        return 1;
    }

    char *ip = argv[1];
    int port;
    if (!(sscanf(argv[2], "%d", &port))) {
        printf("invalid port\n");
    }

    char *command = (char*) malloc(sizeof(char) * BUF_LEN);
    char *ret;
    int ret_;
    printf("Intro\n");

    printf("enter \'help\' to see all available commands\n");
    printf("> ");
    ret = fgets(command, BUF_LEN, stdin);

    while (strcmp(command, "exit") && (ret != NULL)) {
        if (strstr(command, "touch")) {
            printf("called touch\n");
            if ((ret_ = talk(command, ip, port)))
                printf("Error during talk\n");
        }
        else if (strstr(command, "cat")) {
            printf("called cat\n");
            if ((ret_ = talk(command, ip, port)))
                printf("Error during talk\n");
        }
        else if (strstr(command, ">")) {
            printf("called >\n");
            if ((ret_ = talk(command, ip, port)))
                printf("Error during talk\n");
        }
        else if (strstr(command, "rm")) {
            printf("called rm\n");
            if ((ret_ = talk(command, ip, port)))
                printf("Error during talk\n");
        }
        else if (strstr(command, "cd")) {
            printf("called cd\n");
            if ((ret_ = talk(command, ip, port)))
                printf("Error during talk\n");
        }
        else if (strstr(command, "ls")) {
            printf("called ls\n");
            if ((ret_ = talk(command, ip, port)))
                printf("Error during talk\n");
        }
        else if (strstr(command, "cp")) {
            printf("called cp\n");
            if ((ret_ = talk(command, ip, port)))
                printf("Error during talk\n");
        }
        else if (strstr(command, "mv")) {
            printf("called mv\n");
            if ((ret_ = talk(command, ip, port)))
                printf("Error during talk\n");
        }
        else if (strstr(command, "mkdir")) {
            printf("called mkdir\n");
            if ((ret_ = talk(command, ip, port)))
                printf("Error during talk\n");
        }
        else if(strstr(command, "help")) {
            printf("Commands:\n"
            "cd <path>\n"
            "touch <file path>\n"
            "rm <file path>\n"

            );
        }

        printf("> ");
        ret = fgets(command, BUF_LEN, stdin);
    }

    free(command);
}



