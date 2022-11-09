#ifndef CRYPTOGRAM_H
#define CRYPTOGRAM_H

#include <string>
#include <openssl/aes.h>

class Cryptogram
{
public:
    Cryptogram();
    ~Cryptogram();
    //use base64 encode in data; return encode data length and outdata output through encode data
    std::string Base64Encode(const char* in, unsigned int len);
    //use base64 decode in data; return decode data length and outdata output through decode data
    std::string Base64Decode(std::string in);
    std::string Md5Encode(std::string& str);
    char* AesDecode(char* EncryptData, int SetDataLen);
    char* AesEncode(char* source, int& len);
    std::string CreateSalt();
    std::string CreateJwt(std::string& account, std::string& ip);
    bool VertifyJwt(std::string& token, std::string& account, std::string& ip);
    void Init();

private:
    bool IsBase64(const char c);

private:
    unsigned char m_key[AES_BLOCK_SIZE + 1];
    unsigned char m_ivec[AES_BLOCK_SIZE];
    AES_KEY m_aeskey;
    std::string m_base64char = "";

};

#endif // CRYPTOGRAM_H
