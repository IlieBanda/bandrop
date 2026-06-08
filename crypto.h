#pragma once
#include <openssl/evp.h>


class AesEncryptor {
    private: 
    unsigned char key[32];
    unsigned char iv[16];
    public:
    AesEncryptor(std::string password) {
        for(int i=0; i<16; i++) iv[i] = '0';
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, password.c_str(), password.length());
        unsigned int key_len;
        EVP_DigestFinal_ex(mdctx, key, &key_len);
        EVP_MD_CTX_free(mdctx);
    }
    int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
        int len = 0;
        int total_len = 0;
        EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
        total_len = total_len + len;


        EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len);
        total_len = total_len + len;

        EVP_CIPHER_CTX_free(ctx);
        return(total_len);
    }
    int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
        int len = 0;
        int total_len = 0;
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
        total_len = total_len + len;
        if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        total_len = total_len + len;
        EVP_CIPHER_CTX_free(ctx);
        return(total_len);
    }
};

