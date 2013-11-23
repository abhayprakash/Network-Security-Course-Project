#ifndef SECURITYFUNC_H_INCLUDED
#define SECURITYFUNC_H_INCLUDED
#include <mcrypt.h>
#include <iostream>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
using namespace std;
void common_init(MCRYPT &td, char* keyString)
{
    if((td = mcrypt_module_open("des", NULL, "cbc", NULL)) == MCRYPT_FAILED)
    {
        cerr <<"error opening module\n";
        exit(0);
    }

    int keySize =  mcrypt_enc_get_key_size(td);

    if(keySize < strlen(keyString))
    {
        printf("Give a short key of size less than equal to %d\n", keySize);
        exit(0);
    }

    char* key = (char *)malloc(keySize);
    strncpy(key, keyString, strlen(keyString));

    char* IV = (char *)malloc(mcrypt_enc_get_iv_size(td)); /// IMP: The same IV must be used for encryption/decryption
    srand(25);
    for(int i=0;i<mcrypt_enc_get_iv_size(td);i++)
    {
        IV[i] = rand();
    }

    if(mcrypt_generic_init(td, (void *)key, keySize, IV) < 0)
    {
        printf("ERROR in init\n");
        exit(0);
    }
}

void encrypt(FILE* fp, char* msg, char* keyString)
{
    MCRYPT td;
    common_init(td, keyString);

    int blockSize = mcrypt_enc_get_block_size(td);
    int buffSize = ceil(strlen(msg)/(double)blockSize) * blockSize;

    char* msgBuff = (char *)malloc(buffSize);
    strcpy(msgBuff, msg);
    //cout<<"msg size "<<strlen(msg)<<" buff size "<<buffSize<<endl;

    //for(int i = strlen(msg); i < buffSize; i++)
    //    msgBuff[i] = 'x';
    //buffSize = strlen(msgBuff);
    if(mcrypt_generic(td, msgBuff, buffSize) == 0)
    {
        printf("Encryption Success ");
        //printf("Encryption Successful. Flushing encrypted to given file\n");
        //fwrite(msgBuff, 1, buffSize, fp);
        //printf("encrypted data: %s\n", msgBuff);
    }
    else
    {
        printf("Encryption Failure ");
    }
    mcrypt_generic_deinit(td);
    mcrypt_module_close(td);
}

void encryptFile(FILE* in, char* outPath, char* key) // returns the pointer to the encrypted file
{
    FILE* out = fopen(outPath, "wb+");
    MCRYPT td;
    common_init(td, key);

    int blockSize = mcrypt_enc_get_block_size(td);
    char buff[blockSize];

    int nRead;
    while(nRead = fread(buff, 1, blockSize, in))
    {
        //printf("read bytes = %d ", nRead);
        if(mcrypt_generic(td, buff, blockSize) == 0) // last block has less than blocksize (?)
        {
            //printf("Encryption Success ");
            fwrite(buff, 1, blockSize, out); // check with writing only nRead
        }
        else
            printf("Encryption Failure ");
    }
    fclose(out);
    mcrypt_generic_deinit(td);
    mcrypt_module_close(td);
}

void decryptFileToPipe(int writefd, FILE* fp, char* key)
{
    MCRYPT td;
    common_init(td, key);

    int blockSize = mcrypt_enc_get_block_size(td);
    char* block = (char *)malloc(blockSize);
    int n;
    while((n = fread(block, 1, blockSize, fp)) > 0)
    {
       mdecrypt_generic(td, block, n);
       write(writefd, block, n);
    }

    mcrypt_generic_deinit(td);
    mcrypt_module_close(td);
}

#endif // SECURITYFUNC_H_INCLUDED
