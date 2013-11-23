#ifndef SERVERVARIABLES_H_INCLUDED
#define SERVERVARIABLES_H_INCLUDED

const int MAXLN = 4096;
char* key;
char toSendFilePath[256] = "vid1.mp4";
char outFilePath[256] = "encryptedToSend.bin";

map<string, int> AuthTable;

void init_getAuthorizedMACAddresses()
{
    AuthTable["f0:4d:a2:8e:ae:be"] = 1;
}
#endif // SERVERVARIABLES_H_INCLUDED
