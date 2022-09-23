#include"CMyHttpServer.h"
#include"MyDefine.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "database.h"
#include "httpconn.h"
#include <json.hpp>

using json = nlohmann::json;

std::unordered_map<std::string, std::string> CMyHttpServer::m_accounts;

CMyHttpServerMgr::CMyHttpServerMgr(const int& listenPort)
{
    m_listenPort = listenPort;
    m_listenSocket = -1; //windows INVALID_SOCKET
}
CMyHttpServerMgr::~CMyHttpServerMgr()
{
}

int CMyHttpServerMgr::Start()
{
    m_thread = std::move(std::thread([this]() {
        ListenThreadFunc();
        }));
    m_thread.detach();

    return 0;
}

int CMyHttpServerMgr::Stop()
{
    for (auto& httpServer : m_httpServerPool)
    {
        httpServer->Stop();
    }
    return 0;
}

void CMyHttpServerMgr::ListenThreadFunc()
{
    std::cout << "http server listen thread id : " << std::this_thread::get_id() << std::endl;

    //创建监听套接字，并开启监听
    int result = BindSocket(m_listenPort, SOMAXCONN);
    if (0 != result)
    {
        std::cout << "HTTP服务监听套接字创建失败，端口:" << m_listenPort << std::endl;
        return;
    }
    std::cout << "HTTP服务监听端口:" << m_listenPort << std::endl;

    //线程池数量：CPU核数 x 2
    int threadPoolSize = std::thread::hardware_concurrency() * 2;
    for (int i = 0; i < threadPoolSize; i++)
    {
        CMyHttpServerPtr httpServer(new CMyHttpServer(m_listenSocket));
        httpServer->Start();
        m_httpServerPool.push_back(httpServer);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

int CMyHttpServerMgr::BindSocket(int port, int backlog)
{
    //创建监听套接字
    m_listenSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == -1)
    {
        std::cout << "create listen socket failed." << std::endl;
        return -1;
    }

    //地址可复用
    int result = 0, optval = 1;
    result = setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(int));

    //设为非阻塞模式
    int block = 1;
    int flag = fcntl(m_listenSocket, F_GETFL);
    flag |= O_NONBLOCK;
    fcntl(m_listenSocket, F_SETFL, flag);
    //result = ::ioctlsocket(m_listenSocket, FIONBIO, (u_long FAR*) & block);
//    if (SOCKET_ERROR == result)
//    {
//        std::cout << "ioctlsocket failed : " << WSAGetLastError() << std::endl;
//        close(m_listenSocket);
//        m_listenSocket = -1;
//        return -1;
//    }

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(struct sockaddr_in));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    //绑定IP地址和端口
    if (-1 == ::bind(m_listenSocket, (struct sockaddr*)&local_addr, sizeof(struct sockaddr)))
    {
        //std::cout << "bind failed : " << WSAGetLastError() << std::endl;
        close(m_listenSocket);
        m_listenSocket = -1;
        return -1;
    }

    //开启监听
    result = listen(m_listenSocket, backlog);
    if (result < 0)
    {
        //std::cout << "listen failed : " << WSAGetLastError() << std::endl;
        close(m_listenSocket);
        m_listenSocket = -1;
        return -1;
    }
    return 0;
}

CMyHttpServer::CMyHttpServer(const int& listenSocket)
{
    m_base = nullptr;
    m_http = nullptr;
    //m_handle = nullptr;
    m_listenSocket = listenSocket;
    database = Database::GetInstance();
}

CMyHttpServer::~CMyHttpServer()
{
    Stop();
}

int CMyHttpServer::SendReply(struct evhttp_request* pstReq, int code, const char* reason, struct evbuffer* evb)
{
    if (nullptr == pstReq)
    {
        if (evb)
        {
            evbuffer_free(evb);
        }
        return -1;
    }

    //返回HTTP头部
    evhttp_add_header(pstReq->output_headers, "Server", "MyHttpServer");
    evhttp_add_header(pstReq->output_headers, "Content-Type", "application/json");
    evhttp_add_header(pstReq->output_headers, "Connection", "keep-alive");

    //发送应答
    evhttp_send_reply(pstReq, code, reason, evb);
    if (evb)
    {
        evbuffer_free(evb);
    }
    return 0;
}

int CMyHttpServer::Start()
{
    //初始化HTTP请求消息映射表
    struct HTTPReqInfo* cmd = httpReqInfo;
    int index = 0;
    for (; cmd->cmdKey != NULL; cmd++)
    {
        struct HTTPReqInfoMap cmdMap;
        cmdMap.index = index;
        cmdMap.cmd = cmd;
        m_httpReqMap[cmd->cmdKey] = cmdMap;
        index++;
    }

   //create a new work thread and 启动http服务工作线程
    m_thread = std::move(std::thread([this]() {
        WorkThread();
        }));
    m_thread.detach();

    return 0;
}

int CMyHttpServer::Stop()
{
    if (m_base)
    {
        event_base_loopbreak(m_base);
        event_base_free(m_base);
        m_base = nullptr;
    }
    return 0;
}

void CMyHttpServer::WorkThread()
{
    std::cout << "http server work thread id : " << std::this_thread::get_id() << std::endl;

    //创建event base对象
    m_base = event_base_new();
    if (!m_base)
    {
        std::cout << "create event base failed." << std::endl;
        return;
    }
    //创建http server
    m_http = evhttp_new(m_base);
    if (!m_http)
    {
        std::cout << "create evhttp failed." << std::endl;
        goto err;
    }

    //接收新的连接请求
    if (0 != evhttp_accept_socket(m_http, m_listenSocket))
    {
        std::cout << "evhttp accecpt failed." << std::endl;
        goto err;
    }

    //设置HTTP请求超时处理时间，60秒
    evhttp_set_timeout(m_http, 60);

    //设置HTTP支持的请求类型
    evhttp_set_allowed_methods(m_http, EVHTTP_REQ_GET | EVHTTP_REQ_OPTIONS | EVHTTP_REQ_POST);

    //设置http请求回调函数
    evhttp_set_gencb(m_http, HttpReqCallback, this);

    std::cout << "http server started." << std::endl;
    //进入事件循环
    event_base_dispatch(m_base);

err:
    //销毁和释放http server资源
    if(m_http)
        evhttp_free(m_http);

    //销毁和释放event base资源
    if(m_base)
        event_base_free(m_base);
}

void CMyHttpServer::HttpReqCallback(struct evhttp_request* pstReq, void* userData)
{
    std::cout << "HttpReqCallback thread id : " << std::this_thread::get_id() << std::endl;

    evhttp_cmd_type cmdType = evhttp_request_get_command(pstReq);
    const char *uri = evhttp_request_get_uri(pstReq);
    if(strcmp(uri, "/login") == 0)
    {
        printf("login ---------\n");
    }
    else if(strcmp(uri, "/register") == 0)
    {
        printf("register --------\n");
    }

    if (EVHTTP_REQ_GET == cmdType || EVHTTP_REQ_POST == cmdType)
    {
        CMyHttpServer* this_ = (CMyHttpServer*)userData;
        if (!this_)
        {
            std::cout << "get this failed." << std::endl;
            evhttp_send_error(pstReq, HTTP_BADREQUEST, "Bad Request");
            return;
        }
        //URI中包含？的，用于数据请求；否则用于文件请求
        const char* uri = evhttp_request_get_uri(pstReq);
        std::cout<<"request url: "<<uri<<std::endl;
        if (strstr(uri, "?"))
            this_->OnRequestData(pstReq);
        else
            this_->OnRequestFile(pstReq);
    }
    else
    {
        std::cout << "not support request." << std::endl;
        evhttp_send_error(pstReq, HTTP_BADREQUEST, "Bad Request");
    }
}

void CMyHttpServer::OnRequestFile(evhttp_request* pstReq)
{
    if (nullptr == pstReq)
    {
        std::cout << "invalid parameter." << std::endl;
        return;
    }

    evhttp_cmd_type cmdType = evhttp_request_get_command(pstReq);
    if (EVHTTP_REQ_GET == cmdType) //GET请求
    {
        RequestProcessFileGet(pstReq);
    }
    else if (EVHTTP_REQ_POST == cmdType) //POST请求
    {
        RequestProcessFilePost(pstReq);
    }
    else
    {
        std::cout << "not support method." << std::endl;
        SendReply(pstReq, HTTP_BADMETHOD, "NOT-SUPPORT-METHOD", NULL);
    }
    //TODO:文件下载逻辑代码
}

void CMyHttpServer::OnRequestData(struct evhttp_request* pstReq)
{
    if (nullptr == pstReq)
    {
        std::cout << "invalid parameter." << std::endl;
        return;
    }

    evhttp_cmd_type cmdType = evhttp_request_get_command(pstReq);
    if (EVHTTP_REQ_GET == cmdType) //GET请求
    {
        RequestProcessDataGet(pstReq);
    }
    else if (EVHTTP_REQ_POST == cmdType) //POST请求
    {
        RequestProcessDataPost(pstReq);
    }
    else
    {
        std::cout << "not support method." << std::endl;
        SendReply(pstReq, HTTP_BADMETHOD, "NOT-SUPPORT-METHOD", NULL);
    }
}

void CMyHttpServer::RequestProcessFileGet(evhttp_request *pstReq)
{
    std::cout<<"get image"<<std::endl;
    struct evkeyvalq *headers;
    headers = evhttp_request_get_input_headers(pstReq);
    const std::string cookie = evhttp_find_header(headers, "Set-Cookie");
    std::cout<<"get image"<<std::endl;
    if(m_accounts.find(cookie) == m_accounts.end())
    {
        std::cout<<"user is not login"<<std::endl;
    }
    else
    {
        std::cout<<"user is login"<<std::endl;
        std::string account = m_accounts[cookie];
        const std::string uri = evhttp_request_get_uri(pstReq);
        std::string path = database->QueryRoute(account, uri);
        if(path != "")
        {
            path = "/" + account + "/" + path;
            char *savepath = new char[500];
            memset(savepath, 0, 500);
            strcpy(savepath, WORKINGPATH);
            int len = strlen(WORKINGPATH);
            strncpy(savepath + len, path.data(), path.size());

            struct stat filestat;
            if(stat(savepath, &filestat) < 0){
                std::cerr<<"file path error"<<std::endl;
            }

            if(!(filestat.st_mode & S_IROTH)){
                std::cerr<<"file mode fail"<<std::endl;
            }

            if(S_ISDIR(filestat.st_mode)){
                std::cerr<<"path is a director"<<std::endl;
            }

            int fd = open(savepath, O_RDONLY);
            int readindex = 0;
            int readlen = 0;
            char *content = new char[filestat.st_size];
            memset(content, 0, filestat.st_size);
            while(readindex != filestat.st_size)
            {
                readlen = read(fd, content, filestat.st_size - readindex);
                readindex += readlen;
            }
            close(fd);

            struct evbuffer *evb = nullptr;
            evb = evbuffer_new();
            evbuffer_add(evb, content, filestat.st_size);
            evhttp_send_reply(pstReq, 200, "OK", evb);
            evbuffer_free(evb);
            delete [] content;
            delete [] savepath;
        }
        else
        {
            std::cout<<"require image route failed"<<std::endl;
        }

    }

}

void CMyHttpServer::RequestProcessFilePost(evhttp_request *pstReq)
{
    struct evkeyvalq *headers;
    headers = evhttp_request_get_input_headers(pstReq);
    const std::string cookie = evhttp_find_header(headers, "Set-Cookie");
    if(m_accounts.find(cookie) == m_accounts.end())
    {
        std::cout<<"user is not login"<<std::endl;
    }
    else
    {
        std::string account = m_accounts[cookie];
        const std::string uri = evhttp_request_get_uri(pstReq);
        struct evbuffer *buf = evhttp_request_get_input_buffer(pstReq);
        int contentlen = evbuffer_get_length(buf);
        std::cout<<"receve content len: "<<contentlen<<std::endl;
        char *content = new char[contentlen + 1];
        memset(content, 0, contentlen + 1);
        int readindex = 0;
        int readlen = 0;
        while(readindex != contentlen)
        {
            readlen = evbuffer_remove(buf, content, contentlen);
            readindex += readlen;
        }

        std::string subp = database->AddImage(account, uri, std::to_string(contentlen));

        std::cout<<"user is login"<<std::endl;
        account = "/" + account;
        std::cout<<"post"<<std::endl;
        char *savepath = new char[500];
        memset(savepath, 0, 500);
        strcpy(savepath, WORKINGPATH);
        int len = strlen(WORKINGPATH);
        strncpy(savepath + len, account.data(), account.size());
        len = strlen(savepath);

        //        int fd = open(m_real_file, O_WRONLY | O_CREAT);
        //        write(fd, m_content, m_content_length);
        //        close(fd);

        if(subp == "")
        {
            std::cout<<"add image fail"<<std::endl;
        }
        else
        {
            subp = "/" + subp;
            strncpy(savepath + len, subp.data(), subp.size());
            FILE* fp;
            std::cout<<savepath<<std::endl;
            if ((fp = fopen(savepath, "wb+")) == NULL)
            {
                printf("File.\n");

            }
            int l = fwrite(content, 1, contentlen, fp);
            fclose(fp);
            int length = 0;
            Httpconn http;
            char *encode = http.EncodeData(content, length);
//            FILE *fp1 = nullptr;
//            if((fp1 = fopen("wang", "wb+")) == nullptr)
//            {
//                printf("open wang file fail");
//            }
//            else
//            {
//                int l = fwrite(encode, 1, length, fp1);
//                fclose(fp1);
//                std::cout<<"input fp1 "<<l<<" size."<<std::endl;
//            }
//            struct stat filestat;
//            if(stat("wang", &filestat) < 0){
//                std::cout<<"acquire file message fail"<<std::endl;
//            }
//            else
//            {
//                std::cout<<"file size "<<filestat.st_size<<"   "<<length<<std::endl;
//                if((fp1 = fopen("wang", "rb")) == nullptr)
//                {
//                    printf("open wang file fail");
//                }
//                else
//                {
//                    int l = fread(encode, 1, filestat.st_size, fp1);
//                    std::cout<<"read fp1 "<<l<<"size."<<std::endl;
//                }
//            }

            content = http.DecodeData(encode, length);

            std::cout<<"write success "<<l<<std::endl;
        }

        delete[] savepath;
        delete []  content;
        //evhttp_send_reply(pstReq, 200, "OK", nullptr);
    }
    evhttp_send_reply(pstReq, 200, "OK", nullptr);

}

void CMyHttpServer::RequestProcessDataGet(evhttp_request* pstReq)
{
    //TODO：系统各种业务的GET请求
    struct evkeyvalq *headers;
    headers = evhttp_request_get_input_headers(pstReq);
    const std::string cookie = evhttp_find_header(headers, "Set-Cookie");
    if(m_accounts.find(cookie) == m_accounts.end())
    {
        std::cout<<"user is not login"<<std::endl;
    }
    else
    {
        std::cout<<"user is login"<<std::endl;
        std::string account = m_accounts[cookie];
        std::vector<std::string> path;
        if(database->QueryImage(account, path))
        {
            json pathes;
            pathes["pathes"] = path;
            std::string s = pathes.dump();
            char *content = new char[s.size() + 1];
            memset(content,0,s.size() + 1);
            memcpy(content, s.data(), s.size());
            struct evbuffer *evb = nullptr;
            evb = evbuffer_new();
            evbuffer_add(evb, content, strlen(content));
            evhttp_send_reply(pstReq, 200, "OK", evb);
            evbuffer_free(evb);
        }
        else
        {
            std::cerr<<"acquire file list fail"<<std::endl;
            evhttp_send_reply(pstReq, 200, "fail", nullptr);
        }
    }
}

std::string CMyHttpServer::GetContentFromRequest(struct evhttp_request* req)
{
    std::string data;
    struct evbuffer* buf = evhttp_request_get_input_buffer(req);
    while (evbuffer_get_length(buf))
    {
        int n;
        char cbuf[256];
        memset(cbuf, 0, sizeof(cbuf));
        n = evbuffer_remove(buf, cbuf, sizeof(cbuf));
        if (n > 0)
        {
            data.append(cbuf, n);
        }
    }
    return data;
}

void CMyHttpServer::RequestProcessDataPost(evhttp_request* pstReq)
{
    //获取请求URI
    evhttp_cmd_type cmdType = EVHTTP_REQ_POST;
    const char* puri = evhttp_request_get_uri(pstReq);

    struct evkeyvalq headers;
    if (evhttp_parse_query(puri, &headers) != 0)
    {
        std::cout << "http bad request." << std::endl;
        evhttp_send_error(pstReq, HTTP_BADREQUEST, 0);
        return;
    }
    //获取请求方法
    const char* cmd = evhttp_find_header(&headers, "Action");
    if (cmd == NULL)
    {
        std::cout << "http bad request." << std::endl;
        evhttp_send_error(pstReq, HTTP_BADREQUEST, 0);
        return;
    }
    //获取http请求负载数据
    std::string jsonData(std::move(GetContentFromRequest(pstReq)));

    //http请求消息分发
    if (m_httpReqMap.count(cmd) > 0)
    {
        struct HTTPReqInfo* cmdFound = m_httpReqMap.at(cmd).cmd;
        if (cmdFound && cmdFound->called_fun)
        {
            std::string suri(puri);
            std::cout << "POST request uri:" << suri << std::endl << "msg body:" << jsonData << std::endl;

            //触发回调
            cmdFound->called_fun(pstReq, jsonData, this);
        }
        else
        {
            std::cout << "invalid http request cmd : " << cmd << std::endl;
            SendReply(pstReq, HTTP_BADMETHOD, "bad method", NULL);
        }
    }
    else
        std::cout << "no http request cmd." << std::endl;

    SendReply(pstReq, HTTP_OK, "200 OK", NULL);
}

int CMyHttpServer::Login(evhttp_request *pstReq, const string& data, void* param)
{
    std::cout << "recv login request..." << std::endl;

    struct evbuffer *buf;

    struct evkeyvalq *headers;
    struct evkeyval *header;
    headers = evhttp_request_get_input_headers(pstReq);
    for (header = headers->tqh_first; header;
         header = header->next.tqe_next) {
        printf("  %s: %s\n", header->key, header->value);
    }

    evhttp_cmd_type requesttype = evhttp_request_get_command(pstReq);
    printf("Received a login request for %s\nHeaders:\n",
           evhttp_request_get_uri(pstReq));
    if(requesttype == EVHTTP_REQ_POST)
    {
        //printf("Received a %s request for %s\nHeaders:\n",
               //cmdtype, evhttp_request_get_uri(req));

        buf = evhttp_request_get_input_buffer(pstReq);
        int contentlen = evbuffer_get_length(buf);
        char *content = new char[contentlen + 1];
        memset(content, 0, contentlen + 1);
        int readindex = 0;
        int readlen = 0;
        while(readindex != contentlen)
        {
            readlen = evbuffer_remove(buf, content, contentlen);
            readindex += readlen;
        }

        json j3=json::parse(data);

        Database *database = Database::GetInstance();

        evbuffer *evb = nullptr;
        evb = evbuffer_new();
        if(!evb)
        {
            std::cerr<<"new evbuffer fail"<<std::endl;
        }

        if(database->Longin(j3["account"], j3["password"]))
        {
            std::cout<<"Login success"<<std::endl;
            std::string password = j3["password"];
            m_accounts[password] = j3["account"];
            json state;
            state["status"] = "success";
            std::string s = state.dump();

            char *recontent = new char[s.size() + 1];
            memset(recontent,0,s.size() + 1);
            memcpy(recontent, s.data(), s.size());
            printf("reply: %s\n", recontent);
            evbuffer_add(evb, recontent, s.size());
        }
        else
        {
            std::cout<<"Login fail"<<std::endl;
            json state;
            state["status"] = "fail";
            std::string s = state.dump();

            char *recontent = new char[s.size() + 1];
            memset(recontent,0,s.size() + 1);
            memcpy(recontent, s.data(), s.size());
            printf("reply: %s\n", recontent);
            evbuffer_add(evb, recontent, strlen(recontent));
        }

        evhttp_add_header(evhttp_request_get_output_headers(pstReq),"Content-Type", "application/json");
        evhttp_add_header(evhttp_request_get_output_headers(pstReq), "Connection", "keep-alive");

        evhttp_send_reply(pstReq, 200, "OK", evb);

        evbuffer_free(evb);
    }

    //TODO：登录
    return -1;
}

int CMyHttpServer::Logout(evhttp_request* pstReq, const string& data, void* param)
{
    std::cout << "recv logout request..." << std::endl;
    //TODO：登出
    return -1;
}

int CMyHttpServer::Heartbeat(evhttp_request* pstReq, const string& data, void* param)
{
    std::cout << "recv hreatbeat request..." << std::endl;
    //TODO：心跳
    return -1;
}
