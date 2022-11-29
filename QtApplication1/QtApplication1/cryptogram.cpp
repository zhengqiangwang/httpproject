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
    //�ڴ�Դ source
    auto mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio)return result;

    //base64 filter
    auto b64_bio = BIO_new(BIO_f_base64());
    if (!b64_bio)
    {
        BIO_free(mem_bio);
        return result;
    }

    //�γ�BIO��
    //b64-mem
    BIO_push(b64_bio, mem_bio);
    //����64�ֽڲ���ӻ��У�\n��,�����������һ����
    // Ĭ�Ͻ�β�л��з�\n ����64�ֽ������\n
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    // д�뵽base64 filter ���б��룬����ᴫ�ݵ��������һ���ڵ�
    // ��mem�ж�ȡ���(����ͷ����������������)
    // BIO_write ���� 3�ֽ�=��4�ֽ�  ����3�ֽڲ���0 �� =
    // ��������ÿ64�ֽڣ���ȷ�������\n ���з�
    int re = BIO_write(b64_bio, in, len);
    if (re <= 0)
    {
        //�����������ڵ�
        BIO_free_all(b64_bio);
        return 0;
    }

    //ˢ�»��棬д�������mem
    BIO_flush(b64_bio);

    //������Դ�ڴ��ȡ
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
    //�ڴ�Դ �����ģ�
    auto mem_bio = BIO_new_mem_buf(in, len);
    if (!mem_bio)return result;
    //base64 ������
    auto b64_bio = BIO_new(BIO_f_base64());
    if (!b64_bio)
    {
        BIO_free(mem_bio);
        return result;
    }
    //�γ�BIO��
    BIO_push(b64_bio, mem_bio);

    //Ĭ�϶�ȡ���з�������
    //���ú�����������\n��ʧ��
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    //��ȡ ���� 4�ֽ�ת3�ֽ�
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