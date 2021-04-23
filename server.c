#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


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

    while(1) {
	ssize_t len;
	char *strccc = malloc(10 * sizeof(char));

	fprintf(stderr, "reading from socket\n");

        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
	len = read(connfd, strccc, sizeof(strccc));

	fprintf(stderr, "read from socket %d %s\n", len, strccc);
	fprintf(stderr, "length %d\n", len);

	fprintf(stderr, "writing to char device\n");

	int fp = open("/dev/module", O_WRONLY | O_CREAT | O_APPEND);
	len = write(fp, strccc, 10);
	close(fp);

	fprintf(stderr, "wrote to char device %d %s\n", len, strccc);

	fprintf(stderr, "reading from char device\n");

	int fpr = open("/dev/module", O_RDONLY);
	off_t off = lseek(fp, 0, SEEK_SET);

	char *read_str = malloc(1025);

	len = read(fpr, read_str, 1025);
	//read_str[len] = 0;
	close(fpr);

	fprintf(stderr, "read from char_device %d %s\n", len, read_str);

	fprintf(stderr, "writing to socket %s\n", read_str);

        snprintf(sendBuff, strlen(read_str)*sizeof(char), "%s", read_str);
        len = write(connfd, sendBuff, strlen(sendBuff));

	fprintf(stderr, "wrote to socket %d %s\n", strlen(sendBuff), sendBuff);
        close(connfd);
        sleep(1);
     }
}
