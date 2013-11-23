#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
//#include <netdb.h>

#include "securityFunc.h"
#include "clientVariables.h"

int makeConnection(int argc, char ** argv)
{
    int socket_fd, n;
    struct sockaddr_in servaddr;

    if(argc != 3)
    {
        printf("Give IP and port\n");
        return -1;
    }

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(socket_fd < 0)
    {
        printf("Socket opening failure\n");
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(atoi(argv[2]));

    if(inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0)
    {
        printf("address conversion error\n");
        return -1;
    }

    if(connect(socket_fd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0)
    {
        printf("connection error\n");
        return -1;
    }

    return socket_fd;
}

void getMACaddress()
{
    struct ifreq s;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    strcpy(s.ifr_name, "eth0");
    if (ioctl(fd, SIOCGIFHWADDR, &s) == 0)
    {
        printf("Sending MAC Address : ");
        sprintf(MACAddress, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char) s.ifr_addr.sa_data[0], (unsigned char) s.ifr_addr.sa_data[1],(unsigned char) s.ifr_addr.sa_data[2],(unsigned char) s.ifr_addr.sa_data[3],(unsigned char) s.ifr_addr.sa_data[4],(unsigned char) s.ifr_addr.sa_data[5]);
        printf("%s\n", MACAddress);
    }
    close(fd);
}

int getFileFromServer(int socket_fd)
{
    FILE* fp = fopen(recievedEncryptedFilePath, "wb+");

    char buff[MAXLN];

    int nRecieved;
    while((nRecieved = read(socket_fd, buff, MAXLN)))
    {
        fwrite(buff, 1, nRecieved, fp);
    }
    fclose(fp);
}

int closeConnection(int socket_fd)
{
    if(close(socket_fd) < 0)
    {
        printf("close error\n");
        return -1;
    }
    return 0;
}

int askForEncryptionKey(int socket_fd) // write it to extract encryption key using the clientKey (MAC address - simpler way)
{
    key = (char *)malloc(256);
    //strcpy(key, "myKey");
    write(socket_fd, MACAddress, strlen(MACAddress));
    read(socket_fd, key, 256);
    //printf("Key obtained : %s\n", key);
    if(strcmp(key, "NOTAUTH") == 0)
        return 0;

    return 1;
}

int main(int argc, char ** argv)
{
    int socket_fd;

    if((socket_fd = makeConnection(argc, argv)) < 0)
    {
        printf("Problem in Connection Establishment\n");
        return 0;
    }

    getMACaddress();
    if(askForEncryptionKey(socket_fd))
    {
        printf("Got the encrytion key\n");
    }
    else
    {
        printf("Server didn't provide the encryption key\n");
        exit(0);
    }

    if(getFileFromServer(socket_fd)==0)
    {
        printf("Got the encrypted file on client\n");
    }

    if(closeConnection(socket_fd) == 0)
    {
        printf("Connection closed\n");
    }

    int pipeToPlayer[2];
    pipe(pipeToPlayer);
    pid_t player_pid = fork();
    if(player_pid)
    {
        //parent - write decrypted to pipe
        close(pipeToPlayer[0]);
        FILE* fp = fopen(recievedEncryptedFilePath, "rb");
        decryptFileToPipe(pipeToPlayer[1], fp, key);
        fclose(fp);
    }
    else
    {
        //child - read the pipe and play using cvlc
        close(pipeToPlayer[1]);
        char commandToPlay[256];
        sprintf(commandToPlay, "%s pipe:%d", nameOfCapableProgram, pipeToPlayer[0] );
        system(commandToPlay);

        char command[256];
        sprintf(command, "rm %s", recievedEncryptedFilePath);
        system(command);
    }

    //printf("saved the decrypted copy\n");
}
