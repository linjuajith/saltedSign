#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include<openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#define ED25519_DLL 
#include "ed25519.h"

#include "ge.h"
#include "sc.h"
struct block{
unsigned char *salt_signature;
unsigned char *eckey;
unsigned char *filename;
}*head;
struct block *block2;
struct block *block3;
struct block *block4;
struct block *block5;
unsigned char* toString(struct block b)
{
  unsigned char *str=malloc(sizeof(unsigned char)*sizeof(b));
  memcpy(str,&b,sizeof(b));
  return str;
}
/*unsigned char *blake2b_hash(const unsigned char *data, size_t data_len) {
  // Create a BLAKE2b context.
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    return NULL;
  }

  // Initialize the BLAKE2b context.
  if (EVP_DigestInit_ex(ctx, EVP_blake2b512(), NULL) != 1) {
    EVP_MD_CTX_free(ctx);
    return NULL;
  }

  // Update the BLAKE2b context with the data to be hashed.
  if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
    EVP_MD_CTX_free(ctx);
    return NULL;
  }

  // Finalize the BLAKE2b context and get the hash value.
  unsigned char *hash = malloc(SHA512_DIGEST_LENGTH);
  if (hash == NULL) {
    EVP_MD_CTX_free(ctx);
    return NULL;
  }

  unsigned int hash_len = 0;
  if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
    free(hash);
    EVP_MD_CTX_free(ctx);
    return NULL;
  }

  // Free the BLAKE2b context.
  EVP_MD_CTX_free(ctx);

  // Return the hash value.
  return hash;
}*/

int main() {
printf("\n Authentication of first block");
    unsigned char public_key1[32], private_key1[64], seed1[32], scalar1[32];
     unsigned char signature1[64];
     unsigned char nsignature1[64];
    unsigned char *filename1=(unsigned char *)malloc(17);
printf("\n\nPlease Enter the video name: \n");
scanf("%s",filename1);
 ed25519_create_seed(seed1);
    ed25519_create_keypair(public_key1, private_key1, seed1);
     clock_t tic1 = clock();
FILE *file1 = fopen(filename1, "rb");
if (file1 == NULL)
    {
        printf("Error: Invalid file.\n");
    }
    
    long int fileSize1 = 0;
    
    fseek(file1, 0, SEEK_END);
   fileSize1 = ftell(file1);
    fseek(file1, 0, SEEK_SET);
 unsigned char *fileContents1 = (unsigned char*) malloc(sizeof(char) * fileSize1);
   size_t amountRead1 = fread(fileContents1, fileSize1, 1, file1);
  unsigned char hmac1[SHA512_DIGEST_LENGTH];
  unsigned int hmac_len1 = 0;
  unsigned char nhmac1[SHA512_DIGEST_LENGTH];
  unsigned int nhmac_len1 = 0;
  HMAC(EVP_blake2b512(), public_key1, 32, "", sizeof(""), hmac1, &hmac_len1);
//printf("\n hash of video is%s\n",hmac);
ed25519_sign(signature1, hmac1, strlen(hmac1), public_key1, private_key1);
HMAC(EVP_blake2b512(), signature1, 64, fileContents1, amountRead1, nhmac1, &nhmac_len1);
ed25519_sign(nsignature1, nhmac1, 64, public_key1, private_key1);

unsigned char *salted_signature1 = malloc(64 + 64);
  memcpy(salted_signature1, signature1, 64);
  memcpy(salted_signature1 + 64, nsignature1, 64);
   head=malloc(sizeof(struct block)+sizeof(char [strlen(filename1)]));
  head->salt_signature=salted_signature1 ;
head->eckey=public_key1;
 head->filename=filename1;
clock_t toc1 = clock();
printf("Elapsed: %f seconds\n", (double)(toc1 - tic1) / CLOCKS_PER_SEC);

printf("\n Authentication of second block");
unsigned char public_key2[32], private_key2[64], seed2[32], scalar2[32];
     unsigned char signature2[64];
     unsigned char nsignature2[64];
    unsigned char *filename2=(unsigned char *)malloc(17);
printf("\n\nPlease Enter the video name: \n");
scanf("%s",filename2);
 ed25519_create_seed(seed2);
    ed25519_create_keypair(public_key2, private_key2, seed2);
 clock_t tic2 = clock();
FILE *file2 = fopen(filename2, "rb");
if (file2 == NULL)
    {
        printf("Error: Invalid file.\n");
    }
    
    long int fileSize2 = 0;
    
    fseek(file2, 0, SEEK_END);
   fileSize2 = ftell(file2);
    fseek(file2, 0, SEEK_SET);
 unsigned char *fileContents2 = (unsigned char*) malloc(sizeof(char) * fileSize2);
   size_t amountRead2 = fread(fileContents2, fileSize2, 1, file2);
  unsigned char hmac2[SHA512_DIGEST_LENGTH];
  unsigned int hmac_len2 = 0;
  unsigned char nhmac2[SHA512_DIGEST_LENGTH];
  unsigned int nhmac_len2 = 0;
  HMAC(EVP_blake2b512(), public_key2, 32, toString(*head),sizeof(*head), hmac2, &hmac_len2);
//printf("\n hash of video is%s\n",hmac);
ed25519_sign(signature2, hmac2, strlen(hmac2), public_key2, private_key2);
HMAC(EVP_blake2b512(), signature2, 64, fileContents2, amountRead2, nhmac2, &nhmac_len2);
ed25519_sign(nsignature2, nhmac2, 64, public_key2, private_key2);

unsigned char *salted_signature2 = malloc(64 + 64);
  memcpy(salted_signature2, signature2, 64);
  memcpy(salted_signature2 + 64, nsignature2, 64);
   block2=malloc(sizeof(struct block)+sizeof(char [strlen(filename2)]));
  block2->salt_signature=salted_signature2 ;
block2->eckey=public_key2;
 block2->filename=filename2;
clock_t toc2 = clock();
printf("Elapsed: %f seconds\n", (double)(toc2 - tic2) / CLOCKS_PER_SEC);
printf("\n Authentication of third block");
unsigned char public_key3[32], private_key3[64], seed3[32], scalar3[32];
     unsigned char signature3[64];
     unsigned char nsignature3[64];
    unsigned char *filename3=(unsigned char *)malloc(17);
printf("\n\nPlease Enter the video name: \n");
scanf("%s",filename3);
 ed25519_create_seed(seed3);
    ed25519_create_keypair(public_key3, private_key3, seed3);
 clock_t tic3 = clock();
FILE *file3 = fopen(filename3, "rb");
if (file3 == NULL)
    {
        printf("Error: Invalid file.\n");
    }
    
    long int fileSize3 = 0;
    
    fseek(file3, 0, SEEK_END);
   fileSize3 = ftell(file3);
    fseek(file3, 0, SEEK_SET);
 unsigned char *fileContents3 = (unsigned char*) malloc(sizeof(char) * fileSize3);
   size_t amountRead3 = fread(fileContents3, fileSize3, 1, file3);
  unsigned char hmac3[SHA512_DIGEST_LENGTH];
  unsigned int hmac_len3 = 0;
  unsigned char nhmac3[SHA512_DIGEST_LENGTH];
  unsigned int nhmac_len3 = 0;
  HMAC(EVP_blake2b512(), public_key3, 32, toString(*block2),sizeof(*block2), hmac3, &hmac_len3);
//printf("\n hash of video is%s\n",hmac);
ed25519_sign(signature3, hmac3, strlen(hmac3), public_key3, private_key3);
HMAC(EVP_blake2b512(), signature3, 64, fileContents3, amountRead3, nhmac3, &nhmac_len3);
ed25519_sign(nsignature3, nhmac3, 64, public_key3, private_key3);

unsigned char *salted_signature3 = malloc(64 + 64);
  memcpy(salted_signature3, signature3, 64);
  memcpy(salted_signature3 + 64, nsignature3, 64);
   block3=malloc(sizeof(struct block)+sizeof(char [strlen(filename3)]));
  block3->salt_signature=salted_signature3 ;
block3->eckey=public_key3;
 block3->filename=filename3;
clock_t toc3 = clock();
printf("Elapsed: %f seconds\n", (double)(toc3 - tic3) / CLOCKS_PER_SEC);
printf("\n Authentication of fourth block");
unsigned char public_key4[32], private_key4[64], seed4[32], scalar4[32];
     unsigned char signature4[64];
     unsigned char nsignature4[64];
    unsigned char *filename4=(unsigned char *)malloc(17);
printf("\n\nPlease Enter the video name: \n");
scanf("%s",filename4);
 ed25519_create_seed(seed4);
    ed25519_create_keypair(public_key4, private_key4, seed4);
 clock_t tic4 = clock();
FILE *file4 = fopen(filename4, "rb");
if (file4 == NULL)
    {
        printf("Error: Invalid file.\n");
    }
    
    long int fileSize4 = 0;
    
    fseek(file4, 0, SEEK_END);
   fileSize4 = ftell(file4);
    fseek(file4, 0, SEEK_SET);
 unsigned char *fileContents4 = (unsigned char*) malloc(sizeof(char) * fileSize4);
   size_t amountRead4 = fread(fileContents4, fileSize4, 1, file4);
  unsigned char hmac4[SHA512_DIGEST_LENGTH];
  unsigned int hmac_len4 = 0;
  unsigned char nhmac4[SHA512_DIGEST_LENGTH];
  unsigned int nhmac_len4 = 0;
  HMAC(EVP_blake2b512(), public_key4, 32, toString(*block3),sizeof(*block3), hmac4, &hmac_len4);
//printf("\n hash of video is%s\n",hmac);
ed25519_sign(signature4, hmac4, strlen(hmac4), public_key4, private_key4);
HMAC(EVP_blake2b512(), signature4, 64, fileContents4, amountRead4, nhmac4, &nhmac_len4);
ed25519_sign(nsignature4, nhmac4, 64, public_key4, private_key4);

unsigned char *salted_signature4 = malloc(64 + 64);
  memcpy(salted_signature4, signature4, 64);
  memcpy(salted_signature4 + 64, nsignature4, 64);
   block4=malloc(sizeof(struct block)+sizeof(char [strlen(filename4)]));
  block4->salt_signature=salted_signature4 ;
block4->eckey=public_key4;
 block4->filename=filename4;
clock_t toc4 = clock();
printf("Elapsed: %f seconds\n", (double)(toc4 - tic4) / CLOCKS_PER_SEC);
printf("\n Authentication of fifth block");
unsigned char public_key5[32], private_key5[64], seed5[32], scalar5[32];
     unsigned char signature5[64];
     unsigned char nsignature5[64];
    unsigned char *filename5=(unsigned char *)malloc(17);
printf("\n\nPlease Enter the video name: \n");
scanf("%s",filename5);
 ed25519_create_seed(seed5);
    ed25519_create_keypair(public_key5, private_key5, seed5);
 clock_t tic5 = clock();
FILE *file5 = fopen(filename5, "rb");
if (file5 == NULL)
    {
        printf("Error: Invalid file.\n");
    }
    
    long int fileSize5 = 0;
    
    fseek(file5, 0, SEEK_END);
   fileSize5 = ftell(file5);
    fseek(file5, 0, SEEK_SET);
 unsigned char *fileContents5 = (unsigned char*) malloc(sizeof(char) * fileSize5);
   size_t amountRead5 = fread(fileContents5, fileSize5, 1, file5);
  unsigned char hmac5[SHA512_DIGEST_LENGTH];
  unsigned int hmac_len5 = 0;
  unsigned char nhmac5[SHA512_DIGEST_LENGTH];
  unsigned int nhmac_len5 = 0;
  HMAC(EVP_blake2b512(), public_key5, 32, toString(*block4),sizeof(*block4), hmac5, &hmac_len5);
//printf("\n hash of video is%s\n",hmac);
ed25519_sign(signature5, hmac5, strlen(hmac5), public_key5, private_key5);
HMAC(EVP_blake2b512(), signature5, 64, fileContents5, amountRead5, nhmac5, &nhmac_len5);
ed25519_sign(nsignature5, nhmac5, 64, public_key5, private_key5);
unsigned char *salted_signature5 = malloc(64 + 64);
  memcpy(salted_signature5, signature5, 64);
  memcpy(salted_signature5 + 64, nsignature5, 64);
   block5=malloc(sizeof(struct block)+sizeof(char [strlen(filename5)]));
  block5->salt_signature=salted_signature5 ;
block5->eckey=public_key5;
 block5->filename=filename5;
clock_t toc5 = clock();
printf("Elapsed: %f seconds\n", (double)(toc5 - tic5) / CLOCKS_PER_SEC);
printf("verification of first block");
 clock_t vtic1 = clock();
unsigned char *vsalted_signature1 = malloc(64 + 64);
vsalted_signature1 =head->salt_signature;
  unsigned char vsignature1[64];
  memcpy(vsignature1, vsalted_signature1, 64);
  unsigned char vnsignature1[64];
  memcpy(vnsignature1, vsalted_signature1 + 64, 64);
  unsigned char vnhmac1[SHA512_DIGEST_LENGTH];
  unsigned int vnhmac_len1 = 0;
 unsigned char vhmac1[SHA512_DIGEST_LENGTH];
  unsigned int vhmac_len1 = 0;
 
HMAC(EVP_blake2b512(), vsignature1, 64, fileContents1, amountRead1, vnhmac1, &vnhmac_len1);
if (ed25519_verify(vnsignature1, vnhmac1, strlen(vnhmac1), public_key1)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }
HMAC(EVP_blake2b512(), head->eckey, 32, "", sizeof(""), vhmac1, &vhmac_len1);
if (ed25519_verify(vsignature1, vhmac1, strlen(vhmac1), public_key1)) {
        printf("\nvalid signature\n");
    } else {
        printf("invalid signature\n");
    }
    clock_t vtoc1 = clock();
printf("Elapsed: %f seconds\n", (double)(vtoc1 - vtic1) / CLOCKS_PER_SEC);
printf("verification of second block");
 clock_t vtic2 = clock();
unsigned char *vsalted_signature2 = malloc(64 + 64);
vsalted_signature2 =block2->salt_signature;
  unsigned char vsignature2[64];
  memcpy(vsignature2, vsalted_signature2, 64);
  unsigned char vnsignature2[64];
  memcpy(vnsignature2, vsalted_signature2 + 64, 64);
  unsigned char vnhmac2[SHA512_DIGEST_LENGTH];
  unsigned int vnhmac_len2 = 0;
 unsigned char vhmac2[SHA512_DIGEST_LENGTH];
  unsigned int vhmac_len2 = 0;
 HMAC(EVP_blake2b512(), vsignature2, 64, fileContents2, amountRead2, vnhmac2, &vnhmac_len2);
if (ed25519_verify(vnsignature2, vnhmac2, strlen(vnhmac2), public_key2)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }
HMAC(EVP_blake2b512(), block2->eckey, 32, toString(*head),sizeof(*head), vhmac2, &vhmac_len2);
if (ed25519_verify(vsignature2, vhmac2, strlen(vhmac2), public_key2)) {
        printf("\nvalid signature\n");
    } else {
        printf("invalid signature\n");
    }
clock_t vtoc2 = clock();
printf("Elapsed: %f seconds\n", (double)(vtoc2 - vtic2) / CLOCKS_PER_SEC);
printf("verification of third block");
 clock_t vtic3 = clock();
unsigned char *vsalted_signature3 = malloc(64 + 64);
vsalted_signature3 =block3->salt_signature;
  unsigned char vsignature3[64];
  memcpy(vsignature3, vsalted_signature3, 64);
  unsigned char vnsignature3[64];
  memcpy(vnsignature3, vsalted_signature3 + 64, 64);
  unsigned char vnhmac3[SHA512_DIGEST_LENGTH];
  unsigned int vnhmac_len3 = 0;
 unsigned char vhmac3[SHA512_DIGEST_LENGTH];
  unsigned int vhmac_len3 = 0;
 
HMAC(EVP_blake2b512(), vsignature3, 64, fileContents3, amountRead3, vnhmac3, &vnhmac_len3);
if (ed25519_verify(vnsignature3, vnhmac3, strlen(vnhmac3), public_key3)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }
HMAC(EVP_blake2b512(), block3->eckey, 32, toString(*block2),sizeof(*block2), vhmac3, &vhmac_len3);
if (ed25519_verify(vsignature3, vhmac3, strlen(vhmac3), public_key3)) {
        printf("\nvalid signature\n");
    } else {
        printf("invalid signature\n");
    }
clock_t vtoc3 = clock();    
printf("Elapsed: %f seconds\n", (double)(vtoc3 - vtic3) / CLOCKS_PER_SEC);
printf("verification of fourth block");
 clock_t vtic4 = clock();
unsigned char *vsalted_signature4 = malloc(64 + 64);
vsalted_signature4 =block4->salt_signature;
  unsigned char vsignature4[64];
  memcpy(vsignature4, vsalted_signature4, 64);
  unsigned char vnsignature4[64];
  memcpy(vnsignature4, vsalted_signature4 + 64, 64);
  unsigned char vnhmac4[SHA512_DIGEST_LENGTH];
  unsigned int vnhmac_len4 = 0;
 unsigned char vhmac4[SHA512_DIGEST_LENGTH];
  unsigned int vhmac_len4 = 0;
HMAC(EVP_blake2b512(), vsignature4, 64, fileContents4, amountRead4, vnhmac4, &vnhmac_len4);
if (ed25519_verify(vnsignature4, vnhmac4, strlen(vnhmac4), public_key4)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }
HMAC(EVP_blake2b512(), block4->eckey, 32, toString(*block3),sizeof(*block3), vhmac4, &vhmac_len4);
if (ed25519_verify(vsignature4, vhmac4, strlen(vhmac4), public_key4)) {
        printf("\nvalid signature\n");
    } else {
        printf("invalid signature\n");
    }
clock_t vtoc4 = clock();
printf("Elapsed: %f seconds\n", (double)(vtoc4 - vtic4) / CLOCKS_PER_SEC);
printf("verification of fifth block");
 clock_t vtic5 = clock();
unsigned char *vsalted_signature5 = malloc(64 + 64);
vsalted_signature5 =block5->salt_signature;
  unsigned char vsignature5[64];
  memcpy(vsignature5, vsalted_signature5, 64);
  unsigned char vnsignature5[64];
  memcpy(vnsignature5, vsalted_signature5 + 64, 64);
  unsigned char vnhmac5[SHA512_DIGEST_LENGTH];
  unsigned int vnhmac_len5 = 0;
 unsigned char vhmac5[SHA512_DIGEST_LENGTH];
  unsigned int vhmac_len5 = 0;
 
HMAC(EVP_blake2b512(), vsignature5, 64, fileContents5, amountRead5, vnhmac5, &vnhmac_len5);
if (ed25519_verify(vnsignature5, vnhmac5, strlen(vnhmac5), public_key5)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }
HMAC(EVP_blake2b512(), block5->eckey, 32, toString(*block4),sizeof(*block4), vhmac5, &vhmac_len5);
if (ed25519_verify(vsignature5, vhmac5, strlen(vhmac5), public_key5)) {
        printf("\nvalid signature\n");
    } else {
        printf("invalid signature\n");
    }
clock_t vtoc5 = clock();   
printf("Elapsed: %f seconds\n", (double)(vtoc5 - vtic5) / CLOCKS_PER_SEC);
//char *hash=(char *)malloc(SHA512_DIGEST_LENGTH);
//const EVP_MD *md = EVP_blake2b512();
//hash= HMAC(md, "", sizeof(""),fileContents,strlen(fileContents), NULL, NULL);
//blake2b_state hash_state;
  //blake2b_init_param(&hash_state, BLAKE2B_PERSONAL, BLAKE2B_512_DIGEST_LENGTH, NULL, NULL, 0);

  // Update the hash object with the data to be hashed.
  //const char *data = "This is the data to be hashed.";
//  blake2b_update(&hash_state, fileContents,strlen(fileContents));

  // Finalize the hash object.
  //unsigned char hash[BLAKE2B_512_DIGEST_LENGTH];
 // blake2b_final(&hash_state, hash);
 
   // Compute the BLAKE2b hash of the message.
  //unsigned char *hash=blake2b_hash(fileContents, amountRead);

//SHA512(fileContents, sizeof(fileContents), hash);
//printf("\n hash of video is%s\n",hash);
    /* create signature on the message with the keypair */
   /* ed25519_sign(signature, hash, strlen(hash), public_key, private_key);
    head=malloc(sizeof(struct block)+sizeof(char [strlen(filename1)]));
     head->signature=signature ;
printf("\n signature  is %s \n",head->signature);
head->eckey=public_key;
head->filename=filename1;
head->index=ind;

     
fclose(file);*/
//end of first block
/*printf("\n verify first block");
clock_t tic1 = clock();
char *path=head->filename;
FILE *f = fopen(path, "rb");
    if (f == NULL)
    {
        printf("Error: Invalid file.\n");
        //return;
    }
    
    long int fSize = 0;
    
    fseek(f, 0, SEEK_END);
   fSize = ftell(f);
    fseek(f, 0, SEEK_SET);
 unsigned char *fContents = (unsigned char*) malloc(sizeof(char) * fSize);

   size_t amountReadf = fread(fContents, fSize, 1, f);*/

//char hashf[SHA512_DIGEST_LENGTH];
//char *hashf=(char *)malloc(SHA512_DIGEST_LENGTH);
//hashf= HMAC(md, "", sizeof(""),fContents,strlen(fContents), NULL, NULL);
/*blake2b_state hash_state1;
  blake2b_init_param(&hash_state1, BLAKE2B_PERSONAL, BLAKE2B_512_DIGEST_LENGTH, NULL, NULL, 0);
  blake2b_update(&hash_state, fContents,strlen(fContents));
*/
  // Finalize the hash object.
  //unsigned char hashf[BLAKE2B_512_DIGEST_LENGTH];
 // blake2b_final(&hash_state1, hashf);

//SHA512(fContents, sizeof(fContents), hashf);
//unsigned char *headeckey= head->eckey;
//printf("\n ecey  is %s \n",head->eckey);
//printf("\n signature   is %s \n",head->signature);
//unsigned char *headsignature=head->signature;
 //unsigned char *hashf=blake2b_hash(fContents, amountReadf);
/*if (ed25519_verify(head->signature, hashf, strlen(hashf), head->eckey)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }
printf("\n hash of video is%s\n",hashf);
  */   return 0;
}
