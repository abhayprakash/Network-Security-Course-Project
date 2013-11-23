#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <map>
#include <string>
#include <time.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "securityFunc.h"
#include "serverVariables.h"

int giveEncryptionKey(int connfd)
{
    key = (char *)malloc(256);
    strcpy(key, "myKey");

    char requestingMAC[256];
    read(connfd, requestingMAC, 256);

    printf("Request from : %s\n", requestingMAC);

    string strReqMAC(requestingMAC);
    if(AuthTable[strReqMAC] == 1)
    {
        write(connfd, key, strlen(key));
        return 1;
    }
    else
    {
        char msg[256] = "NOTAUTH";
        write(connfd, msg, strlen(msg));
        return 0;
    }
}

int makeConnection(int argc, char ** argv)
{
    int listen_fd, connfd;
    socklen_t length;
    struct sockaddr_in servaddr, cliaddr;

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Socket opening error\n");
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(atoi(argv[1]));

    if(bind(listen_fd, (struct sockaddr*) &servaddr, sizeof(servaddr)) < 0)
    {
        printf("binding error\n");
        return -1;
    }

    if(listen(listen_fd, 1024) < 0)
    {
        printf("listen queue full probably\n");
        return -1;
    }

    length = sizeof(cliaddr);
    if((connfd = accept(listen_fd, (struct sockaddr*) &cliaddr, &length)) < 0)
    {
        printf("accept error\n");
        return -1;
    }
    return connfd;
}

void encryptAndSendFile(int connfd)
{
    FILE* original = fopen(toSendFilePath,"rb");
    encryptFile(original, outFilePath, key);
    fclose(original);

    FILE* sendIt = fopen(outFilePath, "rb");
    char buff[MAXLN];

    int n;
    while((n = fread(buff, 1, MAXLN,sendIt)))
    {
        if(write(connfd, buff, n) < 0)
            printf("ERROR: writing on connfd");
        //else
          //  printf("SUCCESS: writing on connfd");
    }
    printf("SUCCESS: Sent the encrypted file to client\n");
    fclose(sendIt);
}

void closeConnection(int connfd)
{
    if(close(connfd) < 0)
        printf("close error\n");
}

int main(int argc, char ** argv)
{
    init_getAuthorizedMACAddresses();
    int connfd = makeConnection(argc, argv);

    if(connfd < 0)
    {
        printf("Error in connection establishment\n");
        return 0;
    }

    if(giveEncryptionKey(connfd))
    {
        printf("Client authorized\n");
    }
    else
    {
        printf("Unknown Client\n");
        exit(0);
    }
    encryptAndSendFile(connfd);
    closeConnection(connfd);
}
