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

#define COMMAND_LEN 10
#define PATH_LEN 25
#define BUF_LEN 1000
#define ERROR_MSG "no such file or directory"

static char current_path[PATH_LEN] = { 0x00 };


int translate(char *strccc) {
	char* command = (char*) malloc(sizeof(char)*COMMAND_LEN-1);
	char* path = (char*) malloc(sizeof(char)*PATH_LEN-1);
	char* buf = (char*) malloc(sizeof(char)*BUF_LEN);

	int ret = sscanf(strccc, "%s %s %s", command, path, buf);

	if (strstr(command, "cat"))
		command = "c";
	else if  (strstr(command, "touch"))
		command = "a";
	else if  (strstr(command, "rm"))
		command = "r";
	else if  (strstr(command, "mkdir"))
		command = "i";
	else if  (strstr(command, "ls"))
		command = "s";
	else if  (strstr(command, "cd"))
		command = "d";
	else if  (strstr(command, "mv"))
		command = "v";
	else if (strstr(command, "scpt")) {
		command = "t";
	} else if (strstr(command, "scpf")) {
		command = "f";
	} else if  (strstr(command, "cp"))
		command = "p";

	char *newpath = (char*) malloc(PATH_LEN-1);
	strncpy(newpath, path, strlen(path));
	if (current_path[strlen(current_path)-1] == '\n') {
		current_path[strlen(current_path)-1] = 0x00;
	}
	if (!(path[0] == '/')) {
		sprintf(newpath, "%s%s", current_path, path);
	}

	if (ret > 0) {
		sprintf(strccc, "%s %s %s", command, newpath, buf);
		return 0;
	}
	return 1;
}


int main(int argc, char *argv[]) {
    if(argc <= 1) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port;
    if (!(sscanf(argv[1], "%d", &port))) {
        printf("Invalid port\n");
    }

    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;

    char sendBuff[COMMAND_LEN + PATH_LEN + BUF_LEN];

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));
    memset(sendBuff, '0', sizeof(sendBuff));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    listen(listenfd, 10);

    while(1) {
    	int ret;
		ssize_t len;
		char *strccc = malloc(BUF_LEN * sizeof(char));

		fprintf(stderr, "reading from socket\n");

        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
		len = read(connfd, strccc, sizeof(char)*BUF_LEN);

		if ((ret = translate(strccc))) {
			printf("Error during translation\n");
			continue;
		}

		char path[PATH_LEN] = { 0x00 };
		char content[BUF_LEN] = { 0x00 };
		char cmd[COMMAND_LEN+PATH_LEN+BUF_LEN+2] = { 0x00 };

		if (strccc[0] == 't') {

			sscanf(strccc+2, "%s %s", path, content);
			int fp = open("/dev/module", O_WRONLY | O_CREAT | O_APPEND);
			sprintf(cmd, "a %s", path);
			
			len = write(fp, cmd, strlen(cmd));
			close(fp);

			fp = open("/dev/module", O_WRONLY | O_CREAT | O_APPEND);
			sprintf(cmd, "> %s %s", path, content);
			len = write(fp, cmd, BUF_LEN);
			close(fp);

			continue;

		} else if (strccc[0] == 'f') {

			sscanf(strccc+2, "%s", path);
    		int fp = open("/dev/module", O_WRONLY | O_CREAT | O_APPEND);
    		sprintf(cmd, "c %s", path);
			len = write(fp, cmd, strlen(cmd));
			close(fp);

			int fpr = open("/dev/module", O_RDONLY);
			off_t off = lseek(fp, 0, SEEK_SET);
			char *read_str = malloc(COMMAND_LEN + PATH_LEN + BUF_LEN);
			len = read(fpr, read_str, COMMAND_LEN + PATH_LEN + BUF_LEN);

			snprintf(sendBuff, strlen(read_str)*sizeof(char), "%s", read_str);
			len = write(connfd, sendBuff, strlen(sendBuff));
			close(fpr);

			continue;

		} else if (strccc[0] == 'd') {

			int fp = open("/dev/module", O_WRONLY | O_CREAT | O_APPEND);
			len = write(fp, strccc, BUF_LEN);
			close(fp);
			sleep(2);

			int fpr = open("/dev/module", O_RDONLY);
			off_t off = lseek(fp, 0, SEEK_SET);
			char *read_str = malloc(COMMAND_LEN + PATH_LEN + BUF_LEN);
			len = read(fpr, read_str, COMMAND_LEN + PATH_LEN + BUF_LEN);
			close(fpr);

			if (strstr(read_str, "failure")) {
			write(connfd, ERROR_MSG, strlen(ERROR_MSG));
			} else {
			write(connfd, read_str, strlen(read_str));
			printf("read from buff %s\n", read_str);
			strncpy(current_path, read_str, PATH_LEN);
			}
			close(connfd);
			sleep(1);

			continue;
		}

		fprintf(stderr, "writing to char device\n");

		int fp = open("/dev/module", O_WRONLY | O_CREAT | O_APPEND);
		len = write(fp, strccc, strlen(strccc));
		close(fp);

		fprintf(stderr, "wrote to char device %d %s\n", len, strccc);

		fprintf(stderr, "reading from char device\n");

		int fpr = open("/dev/module", O_RDONLY);
		off_t off = lseek(fp, 0, SEEK_SET);

		char *read_str = malloc(COMMAND_LEN + PATH_LEN + BUF_LEN);

		len = read(fpr, read_str, COMMAND_LEN + PATH_LEN + BUF_LEN);
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
