#include <jwt-cpp/jwt.h>
#include <exception>  
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "openssl/hmac.h"
#include "openssl/evp.h" 
#include <string.h>
#include "cryptogram.h"

Cryptogram::Cryptogram()
{
    memset(m_key, 0x00, sizeof(m_key));
    memcpy(m_key, "0123456789abcdef", AES_BLOCK_SIZE);
    m_base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}

Cryptogram::~Cryptogram()
{

}

std::string Cryptogram::Base64Encode(const char* in, unsigned int len)
{
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (len--)
    {
        char_array_3[i++] = *(in++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for (i = 0; (i < 4); i++)
            {
                ret += m_base64char[char_array_4[i]];
            }
            i = 0;
        }
    }
    if (i)
    {
        for (j = i; j < 3; j++)
        {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
        {
            ret += m_base64char[char_array_4[j]];
        }

        while ((i++ < 3))
        {
            ret += '=';
        }

    }
    return ret;
}

std::string Cryptogram::Base64Decode(std::string in)
{
    int in_len = (int)in.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (in[in_] != '=') && IsBase64(in[in_])) {
        char_array_4[i++] = in[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = m_base64char.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = m_base64char.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

std::string Cryptogram::Md5Encode(std::string& str)
{
    unsigned char md5[17] = { 0 };
    char output[33] = { 0 };
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, str.c_str(), str.size());
    MD5_Final(md5, &c);

    auto index = 0;
    for (int i = 0; i < 16; i++) {
        sprintf(&output[index], "%02x", md5[i]);
        index += 2;
    }
    return output;
}

char* Cryptogram::AesDecode(char* EncryptData, int SetDataLen)
{
    int i = 0;
    char* DecryptData = nullptr;

    DecryptData = (char*)calloc(SetDataLen + 1, sizeof(char));
    if (DecryptData == nullptr)
    {
        exit(-1);
    }

    memset(&m_aeskey, 0x00, sizeof(AES_KEY));
    if (AES_set_decrypt_key(m_key, 128, &m_aeskey) < 0)
    {
        exit(-1);
    }

    for (i = 0; i < AES_BLOCK_SIZE; i++)
    {
        m_ivec[i] = 0;
    }

    AES_cbc_encrypt((unsigned char*)EncryptData, (unsigned char*)DecryptData, SetDataLen, &m_aeskey, m_ivec, AES_DECRYPT);
    //std::cout<<"DecryptData:"<<DecryptData<<std::endl;
    return DecryptData;
}

char* Cryptogram::AesEncode(char* source, int& len)
{
    char* InputData = nullptr;
    char* EncryptData = nullptr;

    int DataLen = 0;
    int SetDataLen = 0;
    int i = 0;

    DataLen = len;

    SetDataLen = 0;
    if ((DataLen % AES_BLOCK_SIZE) == 0)
    {
        SetDataLen = DataLen;
    }
    else
    {
        SetDataLen = ((DataLen / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    }
    len = SetDataLen;

    InputData = (char*)calloc(SetDataLen + 1, sizeof(char));
    if (InputData == nullptr)
    {
        exit(-1);
    }
    memcpy(InputData, source, DataLen);

    EncryptData = (char*)calloc(SetDataLen + 1, sizeof(char));
    if (EncryptData == nullptr)
    {
        exit(-1);
    }

    memset(&m_aeskey, 0x00, sizeof(AES_KEY));
    if (AES_set_encrypt_key(m_key, 128, &m_aeskey) < 0)
    {
        exit(-1);
    }

    for (i = 0; i < AES_BLOCK_SIZE; i++)
    {
        m_ivec[i] = 0;
    }

    AES_cbc_encrypt((unsigned char*)InputData, (unsigned char*)EncryptData, SetDataLen, &m_aeskey, m_ivec, AES_ENCRYPT);
    delete InputData;
    return EncryptData;
}

std::string Cryptogram::CreateSalt()
{
    //随机生成两个随机数
    int num1 = rand() % 99999999;
    int num2 = rand() % 99999999;
    std::string salt = "";
    //将这两个随机数转换为字符串后追加到salt中
    salt.append(std::to_string(num1));
    salt.append(std::to_string(num2));
    //salt不够十六位就在后面加0
    int len = salt.size();
    if (len < 16) {
        for (int i = 0; i < 16 - len; i++) {
            salt.append("0");
        }
    }
    return salt;
}

std::string Cryptogram::CreateJwt(std::string& account, std::string& ip)
{
    auto token = jwt::create().set_type("JWS");
    token.set_algorithm("HS256");
    token.set_issuer("server");
    token.set_subject("client");
    token.set_audience(account);
    token.set_payload_claim(account, jwt::claim(ip));

    std::string secret = "sec" + account + "ret";
    std::string result = "";
    result = token.sign(jwt::algorithm::hs256{ secret });
    
    return result;
}

bool Cryptogram::VertifyJwt(std::string& token, std::string& account, std::string& ip)
{
    auto decoded = jwt::decode(token);

    std::string secret = "sec" + account + "ret";
    auto verifier = jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256{ secret })
        .with_issuer("server")
        .with_subject("client")
        .with_audience(account)
        .with_claim(account, jwt::claim(ip));

    try {
        verifier.verify(decoded);
        return true;
    }
    catch (const std::exception& ex)
    {
        //std::cerr << "Error: " << ex.what() << std::endl;
        return false;
    }
    return true;
}

void Cryptogram::Init()
{
    
}

bool Cryptogram::IsBase64(const char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

