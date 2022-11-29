#include "network.h"
#include "logger.h"

#ifdef WIN32

#pragma comment(lib,"ws2_32.lib")
#endif



int main(void)
{
#ifdef  WIN32
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif //  WIN32


	Network network;
	network.Init("", 8888);
    network.Start();
    network.Stop();


#ifdef WIN32
    WSACleanup();
#endif
}

//˫����֤����

//#include <stdio.h>
//#include <stdlib.h>
//#include <errno.h>
//#include <string.h>
//#include <sys/types.h>
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include <WinSock2.h>
//
//#pragma comment(lib,"ws2_32.lib")
//
//#define MAXBUF 1024
//void ShowCerts(SSL* ssl)
//{
//    X509* cert;
//    char* line;
//
//    cert = SSL_get_peer_certificate(ssl);
//    // SSL_get_verify_result()���ص㣬SSL_CTX_set_verify()ֻ�������������ò�û��ִ����֤�����øú����Ż���֤����֤����֤
//    // �����֤��ͨ������ô�����׳��쳣��ֹ����
//    if (SSL_get_verify_result(ssl) == X509_V_OK) {
//        printf("֤����֤ͨ��\n");
//    }
//    if (cert != NULL) {
//        /*printf("����֤����Ϣ:\n");
//        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
//        printf("֤��: %s\n", line);
//        free(line);
//        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
//        printf("�䷢��: %s\n", line);
//        free(line);*/
//        X509_free(cert);
//    }
//    else
//        printf("��֤����Ϣ��\n");
//}
//
//int main(int argc, char** argv) {
//    WSADATA wsaData;
//    WSAStartup(MAKEWORD(2, 2), &wsaData);
//    int sockfd, new_fd;
//    int len;
//    struct sockaddr_in my_addr, their_addr;
//    unsigned int myport, lisnum;
//    char buf[MAXBUF + 1];
//    SSL_CTX* ctx;
//
//    
//    myport = 8888;
//
// 
//   lisnum = 0;
//
//    /* SSL ���ʼ�� */
//    SSL_library_init();
//    /* �������� SSL �㷨 */
//    OpenSSL_add_all_algorithms();
//    /* �������� SSL ������Ϣ */
//    SSL_load_error_strings();
//    /* �� SSL V2 �� V3 ��׼���ݷ�ʽ����һ�� SSL_CTX ���� SSL Content Text */
//    ctx = SSL_CTX_new(SSLv23_server_method());
//    /* Ҳ������ SSLv2_server_method() �� SSLv3_server_method() ������ʾ V2 �� V3��׼ */
//    if (ctx == NULL) {
//        ERR_print_errors_fp(stdout);
//        exit(1);
//    }
//
//    // ˫����֤
//    // SSL_VERIFY_PEER---Ҫ���֤�������֤��û��֤��Ҳ�����
//    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT---Ҫ��ͻ�����Ҫ�ṩ֤�飬����֤���ֵ���ʹ��û��֤��Ҳ�����
//    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
//    // �������θ�֤��
//    if (SSL_CTX_load_verify_locations(ctx, "D:/lib/curl-openssl/ca/ca.crt", NULL) <= 0) {
//        ERR_print_errors_fp(stdout);
//        exit(1);
//    }
//
//    /* �����û�������֤�飬 ��֤���������͸��ͻ��ˡ� ֤��������й�Կ */
//    if (SSL_CTX_use_certificate_file(ctx, "D:/lib/curl-openssl/ca/server.crt", SSL_FILETYPE_PEM) <= 0) {
//        ERR_print_errors_fp(stdout);
//        exit(1);
//    }
//    /* �����û�˽Կ */
//    if (SSL_CTX_use_PrivateKey_file(ctx, "D:/lib/curl-openssl/ca/server_rsa_private.pem.unsecure", SSL_FILETYPE_PEM) <= 0) {
//        ERR_print_errors_fp(stdout);
//        exit(1);
//    }
//    /* ����û�˽Կ�Ƿ���ȷ */
//    if (!SSL_CTX_check_private_key(ctx)) {
//        ERR_print_errors_fp(stdout);
//        exit(1);
//    }
//
//    /* ����һ�� socket ���� */
//    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
//        perror("socket");
//        exit(1);
//    }
//    else
//        printf("socket created\n");
//
//    memset(&my_addr, 0, sizeof(my_addr));
//    my_addr.sin_family = PF_INET;
//    my_addr.sin_port = htons(myport);
//    my_addr.sin_addr.s_addr = INADDR_ANY;
//
//    if (bind(sockfd, (struct sockaddr*)&my_addr, sizeof(struct sockaddr))
//        == -1) {
//        perror("bind");
//        exit(1);
//    }
//    else
//        printf("binded\n");
//
//    if (listen(sockfd, lisnum) == -1) {
//        perror("listen");
//        exit(1);
//    }
//    else
//        printf("begin listen\n");
//
//    while (1) {
//        SSL* ssl;
//        len = sizeof(struct sockaddr);
//        /* �ȴ��ͻ��������� */
//        if ((new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &len))
//            == -1) {
//            perror("accept");
//            exit(errno);
//        }
//        else
//            printf("server: got connection from %s, port %d, socket %d\n",
//                inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port),
//                new_fd);
//
//        /* ���� ctx ����һ���µ� SSL */
//        ssl = SSL_new(ctx);
//        /* �������û��� socket ���뵽 SSL */
//        SSL_set_fd(ssl, new_fd);
//        /* ���� SSL ���� */
//        if (SSL_accept(ssl) == -1) {
//            perror("accept");
//            closesocket(new_fd);
//            break;
//        }
//        ShowCerts(ssl);
//
//        /* ��ʼ����ÿ���������ϵ������շ� */
//        memset(buf, 0, MAXBUF + 1);
//        strcpy(buf, "server->client");
//        /* ����Ϣ���ͻ��� */
//        len = SSL_write(ssl, buf, strlen(buf));
//
//        if (len <= 0) {
//            printf("��Ϣ'%s'����ʧ�ܣ����������%d��������Ϣ��'%s'\n", buf, errno,
//                strerror(errno));
//            goto finish;
//        }
//        else
//            printf("��Ϣ'%s'���ͳɹ�����������%d���ֽڣ�\n", buf, len);
//
//        memset(buf, 0, MAXBUF + 1);
//        /* ���տͻ��˵���Ϣ */
//        len = SSL_read(ssl, buf, MAXBUF);
//        if (len > 0)
//            printf("������Ϣ�ɹ�:'%s'����%d���ֽڵ�����\n", buf, len);
//        else
//            printf("��Ϣ����ʧ�ܣ����������%d��������Ϣ��'%s'\n",
//                errno, strerror(errno));
//        /* ����ÿ���������ϵ������շ����� */
//    finish:
//        /* �ر� SSL ���� */
//        SSL_shutdown(ssl);
//        /* �ͷ� SSL */
//        SSL_free(ssl);
//        /* �ر� socket */
//        closesocket(new_fd);
//    }
//    /* �رռ����� socket */
//    closesocket(sockfd);
//    /* �ͷ� CTX */
//    SSL_CTX_free(ctx);
//    WSACleanup();
//    return 0;
//}




//#ifdef WIN32
//#define FD_SETSIZE 1024
//
//#pragma comment(lib,"ws2_32.lib")
//#endif
//#include <fcntl.h>
//
//#include <event2/event.h>
//#include <event2/buffer.h>
//#include <event2/bufferevent.h>
//
//#include <event2/bufferevent_ssl.h>
//#include <openssl/err.h>
//#include <openssl/ssl.h>
//#include <iostream>
//
//#include <assert.h>
//#include <string.h>
//#include <stdlib.h>
//#include <stdio.h>
//#include <errno.h>
//#include "define.h"
//
//SSL* ssl = nullptr;
//void socket_write_cb(evutil_socket_t fd, short events, void* arg);
//
//SSL* CreateSSL(evutil_socket_t& fd)
//{
//    std::cout << "createssl\n" << std::endl;
//    SSL_CTX* ctx = NULL;
//    SSL* ssl = NULL;
//
//    const SSL_METHOD* meth = SSLv23_server_method();
//    ctx = SSL_CTX_new(meth);
//    if (ctx == NULL)
//    {
//        ERR_print_errors_fp(stdout);
//        return nullptr;
//    }
//
//    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) <= 0)
//    {
//        ERR_print_errors_fp(stdout);
//        return nullptr;
//    }
//
//    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
//    {
//        ERR_print_errors_fp(stdout);
//        return nullptr;
//    }
//
//    if (!SSL_CTX_check_private_key(ctx))
//    {
//        ERR_print_errors_fp(stdout);
//        return nullptr;
//    }
//
//    // �����Ӹ���SSL  
//    ssl = SSL_new(ctx);
//    if (!ssl)
//    {
//        printf("SSL_new error!\n");
//        return NULL;
//    }
//
//    SSL_set_fd(ssl, fd);
//    SSL_set_accept_state(ssl);
//    int ret = 0;
//    do {
//        ret = SSL_do_handshake(ssl);
//        std::cout << "ret:" << ret << std::endl;
//    } while (ret != 1);
//
//    return ssl;
//}
//
//
//void socket_read_cb(evutil_socket_t fd, short events, void* arg)
//{
//    struct event* ev = (struct event*)arg;
//
//    char msg[4096];
//    memset(msg, 0, sizeof(msg));
//    int nLen = SSL_read(ssl, msg, sizeof(msg));
//    std::cout << msg << std::endl;
//    event_assign(ev, event_get_base(ev), event_get_fd(ev), EV_WRITE, socket_write_cb, event_get_callback_arg(ev));
//    event_add(ev, nullptr);
//    
//}
//
//void socket_write_cb(evutil_socket_t fd, short events, void* arg)
//{
//    std::cout << "write cb" << std::endl;
//    char msg[4096];
//    memset(msg, 0, sizeof(msg));
//    strcat(msg, "\n this is from server========server resend to client");
//    SSL_write(ssl, msg, strlen(msg));
//}
//
//void (*readfun)(evutil_socket_t, short, void*);
//
//void do_accept(evutil_socket_t listener, short event, void* arg)
//{
//    std::cout<<"do_accept\n"<<std::endl;
//    struct event_base* base = (struct event_base*)arg;
//    struct sockaddr_storage ss;
//    socklen_t slen = sizeof(ss);
//    evutil_socket_t fd = accept(listener, (struct sockaddr*)&ss, &slen);
//    std::cout << fd << "   "<< FD_SETSIZE << std::endl;
//    if (fd < 0)
//    {
//        perror("accept");
//    }
//    else if (fd > FD_SETSIZE)
//    {
//        closesocket(fd);
//    }
//    else
//    {
//        ssl = CreateSSL(fd);
//        struct event* ev = event_new(NULL, -1, 0, NULL, NULL);
//        //����̬�����Ľṹ����Ϊevent�Ļص�����
//        event_assign(ev, base, fd, EV_READ,
//            socket_read_cb, event_self_cbarg());
//
//        event_add(ev, NULL);
//        
//        std::cout << "del:" << event_del(ev) << std::endl;
//        
//        readfun = socket_read_cb;
//        event_assign(ev, event_get_base(ev), event_get_fd(ev), EV_READ, readfun, event_get_callback_arg(ev));
//        short r = event_get_events(ev);
//        if (r & EV_READ)
//        {
//            std::cout << "EV_READ" << std::endl;
//        }
//        if (r & EV_WRITE)
//        {
//            std::cout << "EV_WRITE" << std::endl;
//        }
//        if (r & EV_PERSIST)
//        {
//            std::cout << "EV_PERSIST" << std::endl;
//        }
//        event_add(ev, nullptr);
//    }
//}
//
//void run(void)
//{
//    
//    evutil_socket_t listener;
//    struct sockaddr_in sin;
//    struct event_base* base;
//    struct event* listener_event;
//
//    base = event_base_new();
//    if (!base)
//        return; /*XXXerr*/
//
//    sin.sin_family = AF_INET;
//    sin.sin_addr.s_addr = INADDR_ANY;
//    sin.sin_port = htons(8888);
//
//    listener = socket(AF_INET, SOCK_STREAM, 0);
//    evutil_make_socket_nonblocking(listener);
//
//#ifndef WIN32
//    {
//        int one = 1;
//        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
//    }
//#endif
//
//    if (bind(listener, (struct sockaddr*)&sin, sizeof(sin)) < 0)
//    {
//        perror("bind");
//        return;
//    }
//    if (listen(listener, 16) < 0)
//    {
//        perror("listen");
//        return;
//    }
//
//    listener_event = event_new(base, listener, EV_READ | EV_PERSIST, do_accept, (void*)base);
//    event_add(listener_event, NULL);
//    std::cout << "enter run" << std::endl;
//    event_base_dispatch(base);
//}
//
//int main(int argc, char** argv)
//{
//#ifdef  WIN32
//	WSADATA wsaData;
//	WSAStartup(MAKEWORD(2, 2), &wsaData);
//#endif //  WIN32
//    setvbuf(stdout, NULL, _IONBF, 0);
//
//    SSL_library_init();
//    SSL_load_error_strings();
//    OpenSSL_add_all_algorithms();
//
//    run();
//#ifdef WIN32
//    WSACleanup();
//#endif
//    return 0;
//}




















//#include <iostream>
//#include <chrono>
//#include <boost/filesystem.hpp>
//#include "logger.h"
//
//int main(void)
//{
//	std::string path = "D:/wang1/wang";
//	boost::filesystem::path full_path(boost::filesystem::initial_path());
//	full_path = boost::filesystem::system_complete(boost::filesystem::path(path, boost::filesystem::native));
//
//	auto a = __LINE__;
//	auto b = __FUNCTION__;
//	auto c = __FILE__;
//	std::cout << __TIME__ << std::endl;
//
//	std::shared_ptr<LOGGER> logger{ LOGGER::GetInstance() };
//	logger->WriteLog(LOG_LEVEL_DEBUG, __FILE__, __FUNCTION__, __LINE__, (char*)"wangzhengqiang %d,%s", 20, "duxing");
//
//	auto now = std::chrono::system_clock::now();
//	//ͨ����ͬ���Ȼ�ȡ���ĺ�����
//	uint64_t dis_millseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count()
//		- std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() * 1000;
//	time_t tt = std::chrono::system_clock::to_time_t(now);
//	auto time_tm = localtime(&tt);
//	char strTime[25] = { 0 };
//	sprintf(strTime, "%d-%02d-%02d %02d:%02d:%02d %03d", time_tm->tm_year + 1900,
//		time_tm->tm_mon + 1, time_tm->tm_mday, time_tm->tm_hour,
//		time_tm->tm_min, time_tm->tm_sec, (int)dis_millseconds);
//	std::cout << strTime << std::endl;
//	std::cout << "��:" << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() << std::endl;
//	std::cout << "����:" << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() << std::endl;
//	std::cout << "΢��:" << std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count() << std::endl;
//	std::cout << "����:" << std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count() << std::endl;
//}
 
 

















 

//#include <event2/event.h>
//#include <event2/listener.h>
//#include <event2/http.h>
//#include <event2/http_struct.h>
//#include <event2/keyvalq_struct.h>
//#include <event2/bufferevent.h>
//#include <event2/buffer.h>
//
//#ifdef WIN32
//#pragma comment(lib,"ws2_32.lib")
//#endif // WIN32
//
//
//#include <string.h>
//#ifndef _WIN32
//#include <signal.h>
//#endif
//#include <iostream>
//#include <string>
//using namespace std;
//#define WEBROOT "." 
//#define DEFAULTINDEX "index.html"
//
//
//int m_listenSocket = -1;
//
//
//int BindSocket(int port, int backlog)
//{
//	//���������׽���
//	m_listenSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//	if (m_listenSocket == -1)
//	{
//		std::cout << "create listen socket failed." << std::endl;
//		return -1;
//	}
//
//	//��ַ�ɸ���
//	int result = 0, optval = 1;
//	result = setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(int));
//
//	//��Ϊ������ģʽ
//#ifdef WIN32
//
//	unsigned long ul = 1;
//
//	int ret = ioctlsocket(m_listenSocket, FIONBIO, (unsigned long*)&ul);//���óɷ�����ģʽ�� 
//
//	if (ret == SOCKET_ERROR)//����ʧ�ܡ�  
//
//	{
//		std::cerr << "setting nonblock failed" << std::endl;
//	}
//#endif
//#ifdef UNIX
//
//	int block = 1;
//	int flag = fcntl(m_listenSocket, F_GETFL);
//	flag |= O_NONBLOCK;
//	fcntl(m_listenSocket, F_SETFL, flag);
//#endif
//
//
//	struct sockaddr_in local_addr;
//	memset(&local_addr, 0, sizeof(struct sockaddr_in));
//	local_addr.sin_family = AF_INET;
//	local_addr.sin_port = htons(port);
//	local_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
//
//	//��IP��ַ�Ͷ˿�
//	if (-1 == ::bind(m_listenSocket, (struct sockaddr*)&local_addr, sizeof(struct sockaddr)))
//	{
//		//std::cout << "bind failed : " << WSAGetLastError() << std::endl;
//#ifdef WIN32
//		closesocket(m_listenSocket);
//#endif 
//
//#ifdef UNIX
//		close(m_listenSocket);
//#endif
//		m_listenSocket = -1;
//		return -1;
//	}
//
//	//��������
//    result = listen(m_listenSocket, backlog);
//	if (result < 0)
//	{
//		//std::cout << "listen failed : " << WSAGetLastError() << std::endl;
//#ifdef WIN32
//		closesocket(m_listenSocket);
//#endif 
//
//#ifdef UNIX
//		close(m_listenSocket);
//#endif
//		m_listenSocket = -1;
//		return -1;
//	}
//	return 0;
//}
//
//void offline_callback(struct evhttp_connection* evcon, void* arg)
//{
//	struct evhttp_request* req = (struct evhttp_request*)arg;
//	if (req)
//	{
//		if (req->uri != NULL)
//		{
//			char* orignal_uri = evhttp_decode_uri(req->uri);
//			if (orignal_uri)
//			{
//				cout << "resquest uri:" << orignal_uri << endl;
//				free(orignal_uri);
//			}
//		}
//	}
//	cout << "client offline..." << endl;
//}
//
///// <summary>
/////  http����Ļص�����
/////  ��Ҫע��ķ��棺
/////		1. ÿ����һ�������ڸ����󱻻ظ�֮ǰ����Ӧ��EV_READ�¼��ᱻ���ã��ظ�֮������´�EV_READ�¼���
/////		2. ÿһ������Ҫ�ظ�����ʹ��������ҲӦ�ûظ�һ��������Ϣ���Ա㼰ʱ��EV_READ��
/////		3. ���EV_READû�򿪣���������Ҳ��ʧЧ���޷���ʱ�ص�ʧЧ�����ӣ�����ڴ�й¶��
/////		4. libevent http���ֻ��ƣ���http pipelineģʽ�£����õײ�TCPЭ��ջ�ķ��ͷ���Ϊ���շ���ȡ������������
///// </summary>
///// <param name="request"></param>
///// <param name="arg"></param>
//void http_cb(struct evhttp_request* request, void* arg)
//{
//	//1 ��ȡ�������������Ϣ
//	const char* uri = evhttp_request_get_uri(request);
//	cout << "uri:" << uri << endl;
//	string cmdtype;
//	switch (evhttp_request_get_command(request))
//	{
//	case EVHTTP_REQ_GET:
//		cmdtype = "GET";
//		break;
//	case EVHTTP_REQ_POST:
//		cmdtype = "POST";
//		break;
//	}
//	cout << "cmdtype:" << cmdtype << endl;
//	// ��Ϣ��ͷ
//	evkeyvalq* headers = evhttp_request_get_input_headers(request);
//	cout << "====== headers ======" << endl;
//	for (evkeyval* p = headers->tqh_first; p != NULL; p = p->next.tqe_next)
//		cout << p->key << ":" << p->value << endl;
//
//	// ��ȡ�ͻ��˷������������� (GETΪ�գ�POST�б���Ϣ  )
//	evbuffer* inbuf = evhttp_request_get_input_buffer(request);
//	char buf[1024] = { 0 };
//	cout << "======= Input data ======" << endl;
//	while (evbuffer_get_length(inbuf))
//	{
//		int n = evbuffer_remove(inbuf, buf, sizeof(buf) - 1);
//		if (n > 0)
//		{
//			buf[n] = '\0';
//			cout << buf << endl;
//		}
//	}
//
//	//2 �ظ������
//	// ״̬�� ��Ϣ��ͷ ��Ӧ����
//	string filepath = WEBROOT;
//	filepath += uri;
//	if (strcmp(uri, "/") == 0)
//	{
//		//Ĭ�ϼ�����ҳ�ļ�
//		filepath += DEFAULTINDEX;
//	}
//	//��Ϣ��ͷ
//
//	//��ȡhtml�ļ���������
//	FILE* fp = fopen(filepath.c_str(), "rb");
//	if (!fp)
//	{
//		evhttp_send_reply(request, HTTP_NOTFOUND, "", 0);
//		return;
//	}
//	evbuffer* outbuf = evhttp_request_get_output_buffer(request);
//	for (;;)
//	{
//		int len = fread(buf, 1, sizeof(buf), fp);
//		if (len <= 0)break;
//		evbuffer_add(outbuf, buf, len);
//	}
//	fclose(fp);
//	evhttp_send_reply(request, HTTP_OK, "", outbuf);
//
//	//3. ������ز�������
//	struct evhttp_connection* conn = evhttp_request_get_connection(request);
//	bufferevent* bev = evhttp_connection_get_bufferevent(conn);
//	int fd = bufferevent_getfd(bev);
//	struct event_base* base = evhttp_connection_get_base(conn);
//	//����(����)���ӵĴ��ʱ��(��ʱ�ᷢ��������̽��)  Ĭ��ʱ��Ϊ50
//	struct timeval timeout = { 10,0 };
//	bufferevent_set_timeouts(bev, &timeout, NULL);
//	// ��⵽�ͻ��˹رջ�������Ͽ�ʱ���ᴥ��evhttp_error_cb����
//	// evhttp_error_cb�ڲ���ִ��evhttp_connection_free����������offline_callback
//	evhttp_connection_set_closecb(conn, offline_callback, request);
//}
//int main()
//{
//#ifdef _WIN32 
//	//��ʼ��socket��
//	WSADATA wsa;
//	WSAStartup(MAKEWORD(2, 2), &wsa);
//#else
//	//����SIGPIPE�ź�
//	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
//		return 1;
//#endif
//
//	std::cout << "test server!\n";
//	//����libevent��������
//	event_base* base = event_base_new();
//	if (base)
//		cout << "event_base_new success!" << endl;
//
//	// http  ������
//	//1	����evhttp������
//	evhttp* http = evhttp_new(base);
//
//	//2  �󶨶˿ں�IP
//	int result = BindSocket(8888, SOMAXCONN);
//	if (0 != result)
//	{
//		std::cout << "HTTP��������׽��ִ���ʧ�ܣ��˿�:" << "8888" << std::endl;
//		return -1;
//	}
//	std::cout << m_listenSocket << std::endl;
//	if (0 != evhttp_accept_socket(http, m_listenSocket))
//	{
//		std::cout << "evhttp accecpt failed." << std::endl;
//	}
//	/*struct evhttp_bound_socket* handle;
//	handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", 8888);
//	if (!handle) {
//		cout << "evhttp_bind_socket failed!" << endl;
//	}*/
//
//	//3   �趨�ص�����
//	evhttp_set_gencb(http, http_cb, 0);
//	//evhttp_set_bevcb();
//	//evhttp_set_cb();
//	if (base)
//		event_base_dispatch(base);
//	if (base)
//		event_base_free(base);
//	if (http)
//		evhttp_free(http);
//#ifdef _WIN32
//	WSACleanup();
//#endif
//	return 0;
//}




