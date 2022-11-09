#ifndef CMYHTTPSERVER_H
#define CMYHTTPSERVER_H


#include"MyHeader.h"
#include"MyHttpCmdDef.h"


class CMyHttpServer;
typedef std::shared_ptr<CMyHttpServer>		CMyHttpServerPtr;
typedef vector<CMyHttpServerPtr>			MyHTTPServerVec;

class Database;
class Cryptogram;

class CMyHttpServerMgr
{
public:
    CMyHttpServerMgr(const int& listenPort);
    ~CMyHttpServerMgr();

    //����http����
    int Start();

    //ֹͣhttp����
    int Stop();

private:
    //�����߳�
    void ListenThreadFunc();

    //�����׽��֣��󶨵�ַ�Ͷ˿ڣ���������
    int BindSocket(int port, int backlog);
private:

    //http��������߳�
    std::thread				m_thread;

    //http server�����˿�
    int						m_listenPort;
    //�����׽���
    int						m_listenSocket;

    //http��Ϣ�����̳߳�
    MyHTTPServerVec			m_httpServerPool;
};

class CMyHttpServer
{
public:

    CMyHttpServer(const int& listenSocket);
    ~CMyHttpServer();

    //����http����
    int Start();
    //ֹͣhttp����
    int Stop();

private:
    //�����ļ�����
    void OnRequestFile(struct evhttp_request* pstReq);

    //������������
    void OnRequestData(struct evhttp_request* pstReq);

    //����ϵͳfile��GET����
    void RequestProcessFileGet(struct evhttp_request* pstReq);

    //����ϵͳfile��POST����
    void RequestProcessFilePost(struct evhttp_request* pstReq);

    //����ϵͳ����ҵ���GET����
    void RequestProcessDataGet(struct evhttp_request* pstReq);

    //����ϵͳ����ҵ���POST����
    void RequestProcessDataPost(struct evhttp_request* pstReq);

    //http����ص�����
    static void HttpReqCallback(struct evhttp_request* pstReq, void* userData);

    //http�����̺߳���
    void WorkThread();

    //��ȡhttp����������
    std::string GetContentFromRequest(struct evhttp_request* req);

    //����http����Ӧ����Ϣ
    int SendReply(struct evhttp_request* pstReq, int code, const char* reason, struct evbuffer* evb);

private:
    static int Register(evhttp_request* pstReq, const string& data, void* param);
    static int Login(evhttp_request* pstReq, const string& data, void* param);
    static int Logout(evhttp_request* pstReq, const string& data, void* param);
    static int Heartbeat(evhttp_request* pstReq, const string& data, void* param);

public:
    static std::unordered_map<std::string, std::string> m_accounts;

private:

    //event base
    event_base* m_base;

    //http server
    evhttp* m_http;

    //�󶨼���socket���
    //evhttp_bound_socket*	m_handle;

    //http�������߳�
    std::thread				m_thread;

    //http�����׽���
    int						m_listenSocket;

    //database handle
    Database* m_database = nullptr;
    Cryptogram* m_cryptogram = nullptr;

private:

    //HTTP������Ϣӳ���б�
    struct HTTPReqInfo httpReqInfo[10] =
    {
        {"Register",     CMyHttpServer::Register,},
        {"Login",		CMyHttpServer::Login,},
        {"Logout",		CMyHttpServer::Logout,},
        {"Heartbeat",	CMyHttpServer::Heartbeat,},
        { NULL }
    };

    HTTP_REQ_INFO_MAP	m_httpReqMap;
};

#endif // CMYHTTPSERVER_H
