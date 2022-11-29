#pragma once
#ifndef HTTP_H
#define HTTP_H

#ifdef WIN32
#include <WinSock2.h>
#endif

#include <string>
#include <unordered_map>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

class Http
{
public:
    Http();
    virtual ~Http();

    //发送post请求
    virtual bool SendPost(void);

    //发送get请求
    virtual bool SendGet(void);

    //设置服务器ip地址
    bool SetIpaddress(std::string ip);

    //设置服务端监听端口
    bool SetPort(int port);

    //设置请求头
    bool SetRequestHeader(std::string key, std::string value);

    //通过key获取请求头的值
    std::string GetRequestHeader(std::string key);

    //设置请求体及其长度
    bool SetRequestContent(const char* content, int len);

    //获取请求体
    char* GetRequestContent(void);

    //设置请求url
    bool SetUrl(const std::string url);

    //获取应答报文
    bool AcquireReply(void);

    //通过key获取应答头
    std::string GetReplyHeader(std::string key);
    
    //获取应答体
    char* GetReplyContent(void);

    //获取应答体的长度
    int GetReplyContentLen(void);

    //清除请求
    void ClearRequest();

    //清除应答内容
    void ClearReply();

public:
    /*解析客户端请求时，主状态机的状态
    * CHECK_STATE_REQUESTLINE:当前正在分析请求行
    * CHECK_STATE_HEADER:当前正在分析头部字段
    * CHECK_STATE_CONTENT:当前正在解析请求体
    */
    enum CHECK_STATE { CHECK_STATE_REQUESTLINE = 0, CHECK_STATE_HEADER, CHECK_STATE_CONTENT };

    /*从状态机的三种可能状态，即行的读取状态，分别表示
    * 1.读取到一个完整的行 2.行出错 3.行数据尚且不完整
    */
    enum LINE_STATUS { LINE_ENTIRE = 0, LINE_ERROR, LINE_OPEN };

    /*服务器处理HTTP请求的可能结果，报文解析的结果
    * NOENTIRE_REQUEST          :  请求不完整，需要继续读取客户数据
    * ENTIRE_REQUEST            :  表示获得了一个完整的客户请求
    * SYNTAXERERROR_REQUEST     :  表示客户请求语法错误
    * NORESOURCE_REQUEST        :  表示服务器没有资源
    * FORBIDDENVISIT_REQUEST    :  表示客户对资源没有足够的访问权限
    * FILE_REQUEST              :  文件请求，获取文件成功
    * INTERNAL_ERROR            :  表示服务器内部错误
    * CLOSED_CONNECTION         :  表示客户端已经关闭连接了
    */
    enum HTTP_CODE {
        NOENTIRE_REQUEST, ENTIRE_REQUEST, SYNTAXERERROR_REQUEST, NORESOURCE_REQUEST,
        FORBIDDENVISIT_REQUEST, FILE_REQUEST, INTERNAL_ERROR, CLOSED_CONNECTION
    };

protected:
    //
    virtual bool WriteData();

    //
    virtual int ReadData(char* outData, int readLength, bool flag);

private:
    //检查IP地址是否有效
    bool CheckIPAddrIsVaild(std::string str);

    //解析一行是否合法
    LINE_STATUS ParseLine();

    //从缓冲区里面读取一行
    char* GetLine();

    //解析应答报文
    HTTP_CODE ParseRequest();

    //解析应答报文首行
    HTTP_CODE ParseReplyFirstLine(std::string content);

    //解析应答报文头
    HTTP_CODE ParseHeader(std::string content);

    //解析应答报文体
    HTTP_CODE ParseContent();

    //获取第一个空格所在的位置，若没有则返回-1否则返回空格的位置
    int SearchSpace(std::string& content, int start);

    //获取第一个字符所在的位置，若没有则返回-1否则返回字符的位置
    int SearchCharacter(std::string& content, int start);

protected:
    std::unordered_map<std::string, std::string> m_requestHeader;   //存放请求头部
    std::unordered_map<std::string, std::string> m_replyHeader;     //存放应答头部信息
    std::string m_ip;                                               //存放服务端ip
    int m_port;                                                     //存放服务端端口
    std::string m_url;                                              //存放请求url
    char* m_content = nullptr;                                      //存放需要发送的内容
    int m_contentLength;                                            //存放需要发送内容的长度
    char* m_replyContent = nullptr;                                 //存放应答内容
    int m_replyContentLength;                                       //存放应答内容的长度


private:
    std::string m_replyVersion;                                     //存放应答请求http版本
    int m_stateCode;                                                //存放应答请求状态码
    std::string m_stateDescription;                                 //存放状态码对应的描述

    int m_bufferSize;                                               //缓冲区空间
    char* m_tmpBuffer = nullptr;                                    //存放缓冲区大小
    int m_checkIndex;                                               //存放解析应答请求位置
    int m_readLength;                                               //存放应答请求读取长度
    int m_readIndex;                                                //存放已经从缓冲区读取的数据长度
    int m_checkState;                                               //存放当前解析状态
};

#endif // HTTP_H