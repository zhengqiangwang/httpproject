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

    //发送post请求
    virtual bool SendPost(void);

    //发送get请求
    virtual bool SendGet(void);

    //接收应答报文回调函数
    static size_t ReceiveData(void* ptr, size_t size, size_t nmemb, void* stream);

    //构建get请求
    bool ConstructGet();

    //构建post请求
    bool ConstructPost();

    //
    virtual bool WriteData();

    //
    virtual int ReadData(char* outData, int readLength, bool flag);

private:
    CURL* m_curl = nullptr;                                         //curl句柄
    std::string m_response = "";                                    //存放curl获取的应答内容
    CURLcode m_res = CURLE_OK;                                      //存放curl请求发送结果
    curl_slist* m_curlHeaders = nullptr;                            //curl构造请求头
    double m_receiveLength = 0;                                       //curl应答报文content的长度
    long long m_readIndex = 0;
};

#endif	// CURLHTTP_H

