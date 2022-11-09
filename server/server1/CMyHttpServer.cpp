#include"CMyHttpServer.h"
#include"MyDefine.h"
#include <string.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include <fcntl.h>
#include "database.h"
#include <nlohmann/json.hpp>
#include "cryptogram.h"
#include <boost/filesystem.hpp>


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
#ifdef WIN32

    unsigned long ul = 1;

    int ret = ioctlsocket(m_listenSocket, FIONBIO, (unsigned long*)&ul);//设置成非阻塞模式。

    if (ret == SOCKET_ERROR)//设置失败。

    {
        std::cerr << "setting nonblock failed" << std::endl;
    }
#else

    int block = 1;
    int flag = fcntl(m_listenSocket, F_GETFL);
    flag |= O_NONBLOCK;
    fcntl(m_listenSocket, F_SETFL, flag);
#endif


    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(struct sockaddr_in));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    //绑定IP地址和端口
    if (-1 == ::bind(m_listenSocket, (struct sockaddr*)&local_addr, sizeof(struct sockaddr)))
    {
        //std::cout << "bind failed : " << WSAGetLastError() << std::endl;
#ifdef WIN32
        closesocket(m_listenSocket);
#else
        close(m_listenSocket);
#endif
        m_listenSocket = -1;
        return -1;
    }

    //开启监听
    result = listen(m_listenSocket, backlog);
    if (result < 0)
    {
        //std::cout << "listen failed : " << WSAGetLastError() << std::endl;
#ifdef WIN32
        closesocket(m_listenSocket);
#else
        close(m_listenSocket);
#endif
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
    m_database = Database::GetInstance();
    m_cryptogram = new Cryptogram;
    m_cryptogram->Init();
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

int CMyHttpServer::Register(evhttp_request* pstReq, const std::string& data, void* param)
{
    std::cout << "recv register request..." << std::endl;

    struct evbuffer* buf;

    struct evkeyvalq* headers;
    struct evkeyval* header;
    headers = evhttp_request_get_input_headers(pstReq);
    for (header = headers->tqh_first; header;
        header = header->next.tqe_next) {
        printf("  %s: %s\n", header->key, header->value);
    }

    evhttp_cmd_type requesttype = evhttp_request_get_command(pstReq);
    printf("Received a register request for %s\nHeaders:\n",
        evhttp_request_get_uri(pstReq));
    if (requesttype == EVHTTP_REQ_POST)
    {
        //printf("Received a %s request for %s\nHeaders:\n",
        //cmdtype, evhttp_request_get_uri(req));

        buf = evhttp_request_get_input_buffer(pstReq);
        int contentlen = evbuffer_get_length(buf);
        char* content = new char[contentlen + 1];
        memset(content, 0, contentlen + 1);
        int readindex = 0;
        int readlen = 0;
        while (readindex != contentlen)
        {
            readlen = evbuffer_remove(buf, content, contentlen);
            readindex += readlen;
        }

        json j3 = json::parse(data);

        Database* database = Database::GetInstance();

        evbuffer* evb = nullptr;
        evb = evbuffer_new();
        if (!evb)
        {
            std::cerr << "new evbuffer fail" << std::endl;
        }

        std::string account = database->Register(j3["name"], j3["password"]);
        if (account != "")
        {
            database->CreateTable(account);

            std::string path = WORKINGPATH;
            path += "/" + account;
            if (!boost::filesystem::is_directory(path))
            {
                std::cout << "begin create path: " << path << std::endl;
                if (!boost::filesystem::create_directory(path))
                {
                    std::cout << "create_directories failed: " << path << std::endl;
                    return -1;
                }
            }
            else
            {
                std::cout << path << " aleardy exist" << std::endl;
            }
            /*int ret = mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
            if (ret && errno == EEXIST)
            {
                std::cout << "dir: " << path << " aleardy exist" << std::endl;
            }
            else if (ret)
            {
                std::cout << "create dir error: " << ret << ", :" << strerror(errno) << std::endl;
                return -1;
            }
            else
            {
                std::cout << "mkdir create dir succ: " << path << std::endl;
            }*/
            std::cout << "Register success" << std::endl;
            json state;
            state["account"] = account;
            std::string s = state.dump();

            char* recontent = new char[s.size() + 1];
            memset(recontent, 0, s.size() + 1);
            memcpy(recontent, s.data(), s.size());
            printf("reply: %s\n", recontent);
            evbuffer_add(evb, recontent, s.size());
        }
        else
        {
            std::cout << "Register fail" << std::endl;
            json state;
            state["account"] = "";
            std::string s = state.dump();

            char* recontent = new char[s.size() + 1];
            memset(recontent, 0, s.size() + 1);
            memcpy(recontent, s.data(), s.size());
            printf("reply: %s\n", recontent);
            evbuffer_add(evb, recontent, strlen(recontent));
        }

        evhttp_add_header(evhttp_request_get_output_headers(pstReq), "Content-Type", "application/json");
        evhttp_add_header(evhttp_request_get_output_headers(pstReq), "Connection", "keep-alive");

        evhttp_send_reply(pstReq, 200, "OK", evb);

        evbuffer_free(evb);
    }

    //TODO：登录
    return -1;
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
    evhttp_set_timeout(m_http, 100000);

    //设置HTTP支持的请求类型
    evhttp_set_allowed_methods(m_http, EVHTTP_REQ_GET | EVHTTP_REQ_OPTIONS | EVHTTP_REQ_POST);

    //设置http请求回调函数
    evhttp_set_gencb(m_http, HttpReqCallback, this);

    std::cout << "http server started." << std::endl;
    //进入事件循环
    event_base_dispatch(m_base);

err:
    //销毁和释放http server资源
    if (m_http)
        evhttp_free(m_http);

    //销毁和释放event base资源
    if (m_base)
        event_base_free(m_base);
}

void CMyHttpServer::HttpReqCallback(struct evhttp_request* pstReq, void* userData)
{
    
    std::cout << "HttpReqCallback thread id : " << std::this_thread::get_id() <<"   host:"<< pstReq->remote_host<< " port:"<<pstReq->remote_port << std::endl;

    evhttp_cmd_type cmdType = evhttp_request_get_command(pstReq);
    const char* uri = evhttp_request_get_uri(pstReq);
    if (strcmp(uri, "/login") == 0)
    {
        printf("login ---------\n");
    }
    else if (strcmp(uri, "/register") == 0)
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
        std::cout << "request url: " << uri << std::endl;
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

void CMyHttpServer::RequestProcessFileGet(evhttp_request* pstReq)
{
    std::cout << "get image" << std::endl;
    struct evkeyvalq* headers;
    headers = evhttp_request_get_input_headers(pstReq);
    const std::string cookie = evhttp_find_header(headers, "Set-Cookie");
    std::cout << "get image" << std::endl;
    if (m_accounts.find(cookie) == m_accounts.end())
    {
        std::cout << "user is not login" << std::endl;
    }
    else
    {
        std::cout << "user is login" << std::endl;
        std::string account = m_accounts[cookie];
        const std::string uri = evhttp_request_get_uri(pstReq);
        std::string path = m_database->QueryRoute(account, uri);
        std::cout << "query path:" << path << std::endl;
        if (path != "")
        {
            path = "/" + account + "/" + path + ".txt";
            char* savepath = new char[500];
            memset(savepath, 0, 500);
            strcpy(savepath, WORKINGPATH);
            int len = strlen(WORKINGPATH);
            strncpy(savepath + len, path.data(), path.size());
            std::cout << savepath << std::endl;

            struct stat filestat;
            if (stat(savepath, &filestat) < 0) {
                std::cerr << "file path error" << std::endl;
            }

            /*if (!(filestat.st_mode & S_IROTH)) {
                std::cerr << "file mode fail" << std::endl;
            }

            if (!boost::filesystem::is_regular_file(path)) {
                std::cerr << "path is a director" << std::endl;
            }*/
            if (boost::filesystem::exists(savepath))
            {
                std::cout << "boost charge file success" << std::endl;
                FILE* fd = fopen(savepath, "rb");
                int readindex = 0;
                int readlen = 0;
                char* content = new char[filestat.st_size];
                memset(content, 0, filestat.st_size);
                while (readindex != filestat.st_size)
                {
                    readlen = fread(content + readindex, 1, filestat.st_size - readindex, fd);
                    readindex += readlen;
                }
                fclose(fd);

                struct evbuffer* evb = nullptr;
                evb = evbuffer_new();
                std::string deba = m_cryptogram->AesDecode(content, filestat.st_size);
                std::string de = m_cryptogram->Base64Decode(deba);
                int imagelen = std::atoi(m_database->QueryLength(account, uri).c_str());
                evbuffer_add(evb, de.c_str(), imagelen);
                evhttp_send_reply(pstReq, 200, "OK", evb);
                evbuffer_free(evb);
                delete[] content;
                delete[] savepath;
            }
        }
        else
        {
            std::cout << "require image route failed" << std::endl;
        }

    }

}

void CMyHttpServer::RequestProcessFilePost(evhttp_request* pstReq)
{
    struct evkeyvalq* headers;
    headers = evhttp_request_get_input_headers(pstReq);
    const std::string cookie = evhttp_find_header(headers, "Set-Cookie");
    if (m_accounts.find(cookie) == m_accounts.end())
    {
        std::cout << "user is not login" << std::endl;
    }
    else
    {
        std::string account = m_accounts[cookie];
        const std::string uri = evhttp_request_get_uri(pstReq);
        struct evbuffer* buf = evhttp_request_get_input_buffer(pstReq);
        int contentlen = evbuffer_get_length(buf);
        std::cout << "receve content len: " << contentlen << std::endl;
        char* content = new char[contentlen + 1];
        memset(content, 0, contentlen + 1);
        int readindex = 0;
        int readlen = 0;
        while (readindex != contentlen)
        {
            readlen = evbuffer_remove(buf, content, contentlen);
            readindex += readlen;
        }

        std::string subp = m_database->AddImage(account, uri, std::to_string(contentlen));

        std::cout << "user is login" << std::endl;
        account = "/" + account;
        std::cout << "post" << std::endl;
        char* savepath = new char[500];
        memset(savepath, 0, 500);
        strcpy(savepath, WORKINGPATH);
        int len = strlen(WORKINGPATH);
        strncpy(savepath + len, account.data(), account.size());
        len = strlen(savepath);

        if (subp == "")
        {
            std::cout << "add image fail" << std::endl;
        }
        else
        {
            subp = "/" + subp + ".txt";
            strncpy(savepath + len, subp.data(), subp.size());
            FILE* fp;
            std::cout << savepath << std::endl;
            //            if ((fp = fopen(savepath, "wb+")) == NULL)
            //            {
            //                printf("File.\n");

            //            }
            //            int l = fwrite(content, 1, contentlen, fp);
            //            fclose(fp);
            int length = 0;
            std::string en = m_cryptogram->Base64Encode(content, contentlen);
            char* enba = new char[en.size()];
            memset(enba, 0, en.size());
            memcpy(enba, en.c_str(), en.size());
            length = en.size();
            char* encode = m_cryptogram->AesEncode(enba, length);
            FILE* fp1 = nullptr;
            if ((fp1 = fopen(savepath, "wb+")) == nullptr)
            {
                printf("open wang file fail");
            }
            else
            {
                int l = fwrite(encode, 1, length, fp1);
                memset(encode, 0, length);
                fclose(fp1);
                std::cout << "input fp1 " << l << " size." << std::endl;
            }
            free(encode);
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

            //            free(content);
            //            content = nullptr;
            //            content = http.DecodeData(encode, length);
            //            std::string deba = content;
            //            std::string de = base64_decode(deba);
            //            std::cout<<"decode success"<<std::endl;
            //            FILE *fp2 = nullptr;
            //            if((fp2 = fopen("wang1", "wb+")) == nullptr)
            //            {
            //                printf("open wang1 file fail");
            //            }
            //            else
            //            {
            //                int l = fwrite(de.c_str(), 1, contentlen, fp2);
            //                fclose(fp2);
            //                std::cout<<"input fp2 "<<l<<" size."<<std::endl;
            //            }

                        //std::cout<<"write success "<<l<<std::endl;
        }

        delete[] savepath;
        delete[]  content;
        //evhttp_send_reply(pstReq, 200, "OK", nullptr);
    }
    evhttp_send_reply(pstReq, 200, "OK", nullptr);

}

void CMyHttpServer::RequestProcessDataGet(evhttp_request* pstReq)
{
    //TODO：系统各种业务的GET请求
    struct evkeyvalq* headers;
    headers = evhttp_request_get_input_headers(pstReq);
    const std::string cookie = evhttp_find_header(headers, "Set-Cookie");
    if (m_accounts.find(cookie) == m_accounts.end())
    {
        std::cout << "user is not login" << std::endl;
    }
    else
    {
        std::cout << "user is login" << std::endl;
        std::string account = m_accounts[cookie];
        std::vector<std::string> path;
        if (m_database->QueryImage(account, path))
        {
            json pathes;
            pathes["paths"] = path;
            std::string s = pathes.dump();
            char* content = new char[s.size() + 1];
            memset(content, 0, s.size() + 1);
            memcpy(content, s.data(), s.size());
            struct evbuffer* evb = nullptr;
            evb = evbuffer_new();
            evbuffer_add(evb, content, strlen(content));
            evhttp_add_header(evhttp_request_get_output_headers(pstReq), "Content-Type", "application/json");
            evhttp_send_reply(pstReq, 200, "OK", evb);
            evbuffer_free(evb);
        }
        else
        {
            std::cerr << "acquire file list fail" << std::endl;
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
        std::cout << "http bad request1." << std::endl;
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

int CMyHttpServer::Login(evhttp_request* pstReq, const string& data, void* param)
{
    std::cout << "recv login request..." << std::endl;

    struct evbuffer* buf;

    struct evkeyvalq* headers;
    struct evkeyval* header;
    headers = evhttp_request_get_input_headers(pstReq);
    for (header = headers->tqh_first; header;
        header = header->next.tqe_next) {
        printf("  %s: %s\n", header->key, header->value);
    }

    evhttp_cmd_type requesttype = evhttp_request_get_command(pstReq);
    printf("Received a login request for %s\nHeaders:\n",
        evhttp_request_get_uri(pstReq));
    if (requesttype == EVHTTP_REQ_POST)
    {
        //printf("Received a %s request for %s\nHeaders:\n",
        //cmdtype, evhttp_request_get_uri(req));

        buf = evhttp_request_get_input_buffer(pstReq);
        int contentlen = evbuffer_get_length(buf);
        char* content = new char[contentlen + 1];
        memset(content, 0, contentlen + 1);
        int readindex = 0;
        int readlen = 0;
        while (readindex != contentlen)
        {
            readlen = evbuffer_remove(buf, content, contentlen);
            readindex += readlen;
        }

        json j3 = json::parse(data);

        Database* database = Database::GetInstance();

        evbuffer* evb = nullptr;
        evb = evbuffer_new();
        if (!evb)
        {
            std::cerr << "new evbuffer fail" << std::endl;
        }

        if (database->Longin(j3["account"], j3["password"]))
        {
            std::cout << "Login success" << std::endl;
            std::string password = j3["password"];
            m_accounts[password] = j3["account"];
            json state;
            state["status"] = "success";
            std::string s = state.dump();

            char* recontent = new char[s.size() + 1];
            memset(recontent, 0, s.size() + 1);
            memcpy(recontent, s.data(), s.size());
            printf("reply: %s\n", recontent);
            evbuffer_add(evb, recontent, s.size());
        }
        else
        {
            std::cout << "Login fail" << std::endl;
            json state;
            state["status"] = "fail";
            std::string s = state.dump();

            char* recontent = new char[s.size() + 1];
            memset(recontent, 0, s.size() + 1);
            memcpy(recontent, s.data(), s.size());
            printf("reply: %s\n", recontent);
            evbuffer_add(evb, recontent, strlen(recontent));
        }

        evhttp_add_header(evhttp_request_get_output_headers(pstReq), "Content-Type", "application/json");
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
