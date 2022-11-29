#pragma once
#ifndef HTTP_H
#define HTTP_H

#ifdef WIN32
#define FD_SETSIZE 1024
#include <winsock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#endif

#include <string>
#include <unordered_map>
#include <openssl/ssl.h>

class Http
{
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

public:
    Http();
    ~Http();

    //发送应答报文
    bool SendReply(void);   

    //做一些初始化工作
    void Init(int sockfd, const sockaddr_in& address, SSL** ssl);

    //设置应答头
    bool SetReplyHeader(std::string key, std::string value);

    //通过key获取请求头的值
    std::string GetRequestHeader(std::string key);

    //设置应答内容及其长度
    bool SetReplyContent(const char* content, int len);

    //获取请求体
    char* GetRequestContent(void);

    //获取应答报文
    HTTP_CODE AcquireRequest(void);

    //通过key获取应答头
    std::string GetReplyHeader(std::string key);

    //获取应答体
    char* GetReplyContent(void);

    //获取应答体的长度
    int GetReplyContentLen(void);

    //获取请求体的长度
    int GetRequestContentLen(void);

    //清除请求
    void ClearRequest(void);

    //清除应答内容
    void ClearReply(void);

    //获取请求方法
    std::string GetMethod(void);

    //获取请求url
    std::string GetUrl(void);

    //设置应答报文状态码
    bool SetStateCode(int statecode);


private:
    //自己通过socket发送请求以及读取并解析http请求

    //构造应答报文
    bool ConstructReply();

    //构建应答首行
    std::string ConstructHeaderLine();

    //构建应答头
    std::string ConstructHeaders(std::string statueLine);
    
    //构建应答体
    bool ConstructContent(std::string headers);

    //往套接字里面写数据，发往客户端
    bool WriteData(int socketFd, const char* data, int writeLength);

    //从套接字里面读数据
    int ReadData(int socketFd, char* outData, int readLength);

    //关闭和服务器的连接
    void CloseLink(int socketFd);

    //更改epoll文件描述符
    bool ModeEpollEvent(int epollfd, int fd, int type);


    //解析一行是否合法
    LINE_STATUS ParseLine();

    //从缓冲区里面读取一行
    char* GetLine();

    //解析应答报文
    HTTP_CODE ParseRequest();

    //解析应答报文首行
    HTTP_CODE ParseRequestFirstLine(std::string content);

    //解析应答报文头
    HTTP_CODE ParseHeader(std::string content);

    //解析应答报文体
    HTTP_CODE ParseContent();


    //获取第一个空格所在的位置，若没有则返回-1否则返回空格的位置
    int SearchSpace(std::string& content, int start);

    //获取第一个字符所在的位置，若没有则返回-1否则返回字符的位置
    int SearchCharacter(std::string& content, int start);

    //初始化状态码和对应的英文描述
    void InitDescription(std::unordered_map<int, std::string>& description);

private:
    std::unordered_map<std::string, std::string> m_requestHeader;   //存放客户端请求头部
    std::unordered_map<std::string, std::string> m_replyHeader;     //存放应答客户端头部信息
    std::unordered_map<int, std::string> m_description;             //存放状态码及其对应的描述
    std::string m_url;                                              //存放请求url
    char* m_requestContent = nullptr;                               //存放客户端发送的内容
    int m_requestContentLength;                                     //存放客户端发送内容的长度
    char* m_replyContent = nullptr;                                 //存放应答客户端内容
    int m_replyContentLength;                                       //存放应答客户端内容的长度
    int m_replyLength;                                              //存放应答报文的整个长度
    int m_socketFd;                                                 //存放客户端套接字文件描述符
    sockaddr_in m_address;                                          //存放客户端地址信息


    std::string m_requestVersion;                                   //存放http请求版本
    std::string m_httpVersion;                                      //存放http应答版本
    int m_stateCode;                                                //存放应答状态码
    std::string m_stateDescription;                                 //存放状态码对应的描述
    std::string m_requestMethod;                                    //存放请求的方法

    int m_bufferSize;                                               //缓冲区空间
    char* m_tmpBuffer = nullptr;                                    //存放缓冲区大小
    int m_checkIndex;                                               //存放解析应答请求位置
    int m_readLength;                                               //存放应答请求读取长度
    int m_readIndex;                                                //存放已经从缓冲区读取的数据长度
    int m_checkState;                                               //存放当前解析状态

    char* m_reply = nullptr;                                        //应答报文
    SSL* m_ssl = nullptr;

};

#endif // HTTP_H