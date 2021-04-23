#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>


int main(int argc, char *argv[]) {
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;

    char sendBuff[1025];
    time_t ticks;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));
    memset(sendBuff, '0', sizeof(sendBuff));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5000);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    listen(listenfd, 10);

    int fp = open("/dev/module"/, O_RDONLY);
    printf("FP=%d\n", fp);

    off_t off = lseek(fp, 0, SEEK_SET);
    ssize_t len = read(fp, str, sizeof str);
    str[len]=0;
    printf("%d, %d=%s\n", len, static_cast<int>(off), str);

    close(fp);

    while(1) {
        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
                                                                                                                                                                              
        snprintf(sendBuff, sizeof(sendBuff), "Ground to major bye-bye Tom\n");
        write(connfd, sendBuff, strlen(sendBuff));

        close(connfd);
        sleep(1);
     }
}