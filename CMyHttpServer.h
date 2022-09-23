#ifndef CMYHTTPSERVER_H
#define CMYHTTPSERVER_H


#include"MyHeader.h"
#include"MyHttpCmdDef.h"

/*****************************************************************************
**FileName: MyHeader.h
**Function: http服务器启动/停止，接收客户端http请求及处理
**Version record:
**Version       Author        Data            Description
**v1.0.0        chexlong      2022.09         初稿
**v1.0.2        chexlong	  2022.09         1，支持多线程
**											  2，添加HTTP请求命令模式
*****************************************************************************/

class CMyHttpServer;
typedef std::shared_ptr<CMyHttpServer>		CMyHttpServerPtr;
typedef vector<CMyHttpServerPtr>			MyHTTPServerVec;

class Database;

class CMyHttpServerMgr
{
public:
    CMyHttpServerMgr(const int& listenPort);
    ~CMyHttpServerMgr();

    //启动http服务
    int Start();

    //停止http服务
    int Stop();

private:
    //监听线程
    void ListenThreadFunc();

    //创建套接字，绑定地址和端口，开启监听
    int BindSocket(int port, int backlog);
private:

    //http服务监听线程
    std::thread				m_thread;

    //http server监听端口
    int						m_listenPort;
    //监听套接字
    int						m_listenSocket;

    //http消息处理线程池
    MyHTTPServerVec			m_httpServerPool;
};

class CMyHttpServer
{
public:

    CMyHttpServer(const int& listenSocket);
    ~CMyHttpServer();

    //启动http服务
    int Start();
    //停止http服务
    int Stop();

private:
    //处理文件请求
    void OnRequestFile(struct evhttp_request* pstReq);

    //处理数据请求
    void OnRequestData(struct evhttp_request* pstReq);

    //处理系统file的GET请求
    void RequestProcessFileGet(struct evhttp_request* pstReq);

    //处理系统file的POST请求
    void RequestProcessFilePost(struct evhttp_request* pstReq);

    //处理系统各种业务的GET请求
    void RequestProcessDataGet(struct evhttp_request* pstReq);

    //处理系统各种业务的POST请求
    void RequestProcessDataPost(struct evhttp_request* pstReq);

    //http请求回调函数
    static void HttpReqCallback(struct evhttp_request* pstReq, void* userData);

    //http工作线程函数
    void WorkThread();

    //获取http请求负载数据
    std::string GetContentFromRequest(struct evhttp_request* req);

    //发送http请求应答消息
    int SendReply(struct evhttp_request* pstReq, int code, const char* reason, struct evbuffer* evb);

private:
    static int Login(evhttp_request *pstReq, const string& data, void* param);
    static int Logout(evhttp_request* pstReq, const string& data, void* param);
    static int Heartbeat(evhttp_request *pstReq, const string& data, void* param);

public:
public:
    static std::unordered_map<std::string, std::string> m_accounts;

private:

    //event base
    event_base*				m_base;

    //http server
    evhttp*					m_http;

    //绑定监听socket句柄
    //evhttp_bound_socket*	m_handle;

    //http服务工作线程
    std::thread				m_thread;

    //http监听套接字
    int						m_listenSocket;

    //database handle
    Database *database = nullptr;

private:

    //HTTP请求消息映射列表
    struct HTTPReqInfo httpReqInfo[10] =
    {
        {"Login",		CMyHttpServer::Login,},
        {"Logout",		CMyHttpServer::Logout,},
        {"Heartbeat",	CMyHttpServer::Heartbeat,},
        { NULL }
    };

    HTTP_REQ_INFO_MAP	m_httpReqMap;
};

#endif // CMYHTTPSERVER_H
