#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Usage: %s file_name [hash]\n", argv[0]);
    exit(1);
  }
  
  int bytes_read;
  FILE* input_file;
  int input_file_size;
  char* file_name;
  char *pos;
  char *hash_hex;
  int i;
  
  printf("Calculating hashes...\n");

  file_name = argv[1];

  input_file = fopen(file_name,"rb");
  if ((long)input_file < 1) {
    fprintf(stderr, "File not found\n");
    exit(1);
  }
  fseek(input_file, 0L, SEEK_END);
  input_file_size = ftell(input_file);
  rewind(input_file);

  unsigned char indata[input_file_size];

  bytes_read = fread(indata, 1, input_file_size, input_file);
  
  // Generate hashes
  unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
  unsigned char md5_digest[MD5_DIGEST_LENGTH];
  
  SHA256(indata, input_file_size, sha256_digest);
  MD5(indata, input_file_size, md5_digest);
  
  if (argc < 3) {
    printf("SHA256: ");
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      printf("%02x", sha256_digest[i]);
    }
    printf("\n");
    printf("MD5: ");
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
      printf("%02x", md5_digest[i]);
    }
    printf("\n");
  }
  
  if (argc > 2) {
    hash_hex = argv[2];
    int hash_len = strlen(hash_hex) / 2 + strlen(hash_hex) % 2;
    unsigned char hash_bytes[hash_len];
    
    pos = hash_hex;
    for (i = 0; i < hash_len; i++) {
      sscanf(pos, "%2hhx", &hash_bytes[i]);
      pos += 2;
    }
    
    // printf("Hash len: %d | SHA256 len: %d | MD5 len: %d\n", hash_len, SHA256_DIGEST_LENGTH, MD5_DIGEST_LENGTH);
    
    char hashes_match = 0;
    if (hash_len == SHA256_DIGEST_LENGTH) {
      for (i = 0; i < hash_len; i++) {
        // printf("SHA256 byte: %02x | Hash byte: %02x | Hashes match: %02x\n", sha256_digest[i], hash_bytes[i], hashes_match);
        hashes_match |= sha256_digest[i] ^ hash_bytes[i];
      }
    } else if (hash_len == MD5_DIGEST_LENGTH) {
      for (i = 0; i < hash_len; i++) {
        hashes_match |= md5_digest[i] ^ hash_bytes[i];
        // printf("MD5 byte: %02x | Hash byte: %02x | Hashes match: %02x\n", md5_digest[i], hash_bytes[i], hashes_match);
      }
    } else {
      printf("Hash length does not match available hashes\n");
      exit(1);
    }
    if (hashes_match == 0) {
      printf("Hashes match\n");
    } else {
      printf("Hashes do not match\n");
    }
  }
}
