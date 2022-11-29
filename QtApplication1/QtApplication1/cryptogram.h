#ifndef CRYPTOGRAM_H
#define CRYPTOGRAM_H

#include <string>

class Cryptogram
{
public:
    Cryptogram();
    ~Cryptogram();

    //use base64 encode in data; return encode data length and outdata output through encode data
    std::string Base64Encode(const char* in, int len);

    //use base64 decode in data; return decode data length and outdata output through decode data
    std::string Base64Decode(const char* in, int len);

    //½øÐÐmd5±àÂë
    std::string Md5Encode(std::string& str);
};

#endif // CRYPTOGRAM_H