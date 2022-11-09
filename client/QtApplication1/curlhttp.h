#pragma once
#ifndef CURLHTTP_H
#define CURLHTTP_H

#include <string>
#include "http.h"

class CurlHttp: public Http
{
public:
    CurlHttp();

    ~CurlHttp();

    //����post����
    virtual bool SendPost(void);

    //����get����
    virtual bool SendGet(void);

    //����Ӧ���Ļص�����
    static size_t ReceiveData(void* ptr, size_t size, size_t nmemb, void* stream);

    //����get����
    bool ConstructGet();

    //����post����
    bool ConstructPost();

    //
    virtual bool WriteData();

    //
    virtual int ReadData(char* outData, int readLength, bool flag);

private:
    CURL* m_curl = nullptr;                                         //curl���
    std::string m_response = "";                                    //���curl��ȡ��Ӧ������
    CURLcode m_res = CURLE_OK;                                      //���curl�����ͽ��
    curl_slist* m_curlHeaders = nullptr;                            //curl��������ͷ
    double m_receiveLength = 0;                                       //curlӦ����content�ĳ���
    long long m_readIndex = 0;
};

#endif	// CURLHTTP_H

