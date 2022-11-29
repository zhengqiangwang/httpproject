#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>
#include "cryptogram.h"

Cryptogram::Cryptogram()
{

}

Cryptogram::~Cryptogram()
{

}

std::string Cryptogram::Base64Encode(const char* in, int len)
{
    std::string result = "";
    if (!in || len <= 0)
    {
        return result;
    }
    //内存源 source
    auto mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio)return result;

    //base64 filter
    auto b64_bio = BIO_new(BIO_f_base64());
    if (!b64_bio)
    {
        BIO_free(mem_bio);
        return result;
    }

    //形成BIO链
    //b64-mem
    BIO_push(b64_bio, mem_bio);
    //超过64字节不添加换行（\n）,编码的数据在一行中
    // 默认结尾有换行符\n 超过64字节再添加\n
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    // 写入到base64 filter 进行编码，结果会传递到链表的下一个节点
    // 到mem中读取结果(链表头部代表了整个链表)
    // BIO_write 编码 3字节=》4字节  不足3字节补充0 和 =
    // 编码数据每64字节（不确定）会加\n 换行符
    int re = BIO_write(b64_bio, in, len);
    if (re <= 0)
    {
        //情况整个链表节点
        BIO_free_all(b64_bio);
        return 0;
    }

    //刷新缓存，写入链表的mem
    BIO_flush(b64_bio);

    //从链表源内存读取
    BUF_MEM* p_data = 0;
    BIO_get_mem_ptr(b64_bio, &p_data);
    if (p_data)
    {
        char *outData = new char[p_data->length + 1];
        memset(outData, 0, p_data->length + 1);
        memcpy(outData, p_data->data, p_data->length);
        result = (char*)outData;
        delete[] outData;
    }
    BIO_free_all(b64_bio);

    return result;
}

std::string Cryptogram::Base64Decode(const char* in, int len)
{
    std::string result = "";
    if (!in || len <= 0)
    {
        return result;
    }
    //内存源 （密文）
    auto mem_bio = BIO_new_mem_buf(in, len);
    if (!mem_bio)return result;
    //base64 过滤器
    auto b64_bio = BIO_new(BIO_f_base64());
    if (!b64_bio)
    {
        BIO_free(mem_bio);
        return result;
    }
    //形成BIO链
    BIO_push(b64_bio, mem_bio);

    //默认读取换行符做结束
    //设置后编码中如果有\n会失败
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    //读取 解码 4字节转3字节
    size_t size = 0;
    char *outData = new char[len];
    BIO_read_ex(b64_bio, outData, len, &size);
    BIO_free_all(b64_bio);
    result = (char*)outData;
    delete[] outData;
    return result;
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