//#include "server1.h"
//#include "define.h"
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include <openssl/rand.h>
//
//#include <event.h>
//#include <event2/listener.h>
//#include <event2/bufferevent_ssl.h>
//
//#define SERVER_CRT "server.crt"
//#define SERVER_KEY "server.key"
//#define SERVER_PORT 9999
//static void
//ssl_readcb(struct bufferevent* bev, void* arg)
//{
//    struct evbuffer* in = bufferevent_get_input(bev);
//
//    printf("Received %zu bytes\n", evbuffer_get_length(in));
//    printf("----- data ----\n");
//    printf("%.*s\n", (int)evbuffer_get_length(in), evbuffer_pullup(in, -1));
//
//    bufferevent_write_buffer(bev, in);
//}
//
//static void
//ssl_acceptcb(struct evconnlistener* serv, evutil_socket_t sock, struct sockaddr* sa,
//    int sa_len, void* arg)
//{
//    struct event_base* evbase;
//    struct bufferevent* bev;
//    SSL_CTX* server_ctx;
//    SSL* client_ctx;
//
//    server_ctx = (SSL_CTX*)arg;
//    client_ctx = SSL_new(server_ctx);
//    evbase = evconnlistener_get_base(serv);
//
//    bev = bufferevent_openssl_socket_new(evbase, sock, client_ctx,
//        BUFFEREVENT_SSL_ACCEPTING,
//        BEV_OPT_CLOSE_ON_FREE);
//
//    bufferevent_enable(bev, EV_READ);
//    bufferevent_setcb(bev, ssl_readcb, NULL, NULL, NULL);
//}
//
//static SSL_CTX*
//evssl_init(void)
//{
//    SSL_CTX* server_ctx;
//
//    /* 初始化openssl库 */
//    SSL_load_error_strings();
//    SSL_library_init();
//    /* 初始化随机种子 */
//    if (!RAND_poll())
//        return NULL;
//
//    server_ctx = SSL_CTX_new(SSLv23_server_method());
//
//    if (!SSL_CTX_use_certificate_chain_file(server_ctx, SERVER_CRT) ||
//        !SSL_CTX_use_PrivateKey_file(server_ctx, SERVER_KEY, SSL_FILETYPE_PEM)) {
//        puts("Couldn't read 'server.key' or 'server.crt' file.  To generate a key\n"
//            "To generate a key and certificate, run:\n"
//            "  openssl genrsa -out server.key 2048\n"
//            "  openssl req -new -key server.key -out server.crt.req\n"
//            "  openssl x509 -req -days 365 -in server.crt.req -signkey server.key -out server.crt");
//        return NULL;
//    }
//    SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);
//
//    return server_ctx;
//}
//
//SERVER::SERVER()
//{
//}
//
//SERVER::~SERVER()
//{
//}
//
//SSL_CTX* SERVER::CreateCtx()
//{
//    SSL_CTX* ctx;
//    SSL_library_init();
//    OpenSSL_add_all_algorithms();
//    SSL_load_error_strings();
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
//	return ctx;
//}
//
//int SERVER::Text()
//{
//    SSL_CTX* ctx;
//    struct evconnlistener* listener;
//    struct event_base* evbase;
//    struct sockaddr_in sin;
//
//    memset(&sin, 0, sizeof(sin));
//    sin.sin_family = AF_INET;
//    sin.sin_port = htons(SERVER_PORT);
//    sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
//
//    ctx = evssl_init();
//    if (ctx == NULL) {
//        return 1;
//    }
//    evbase = event_base_new();
//    listener = evconnlistener_new_bind(
//        evbase, ssl_acceptcb, (void*)ctx,
//        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 1024,
//        (struct sockaddr*)&sin, sizeof(sin));
//
//    event_base_loop(evbase, 0);
//
//    evconnlistener_free(listener);
//    SSL_CTX_free(ctx);
//
//    return 0;
//}
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
////// server1.cpp: 定义应用程序的入口点。
//////
////
////#include "server1.h"
////#include <WinSock2.h>
////#include <ws2tcpip.h>
////#include <Windows.h>
////
////#pragma comment(lib,"ws2_32.lib")
////
////#include "database.h"
////
////
////#include <stdio.h>
////#include <mutex>
////#include <thread>
////#include <string>
////#include <map>
////#include <vector>
////#include <iostream>
////#include <memory>
////#include <unordered_map>
////#include <string.h>
////
////#include "event2/bufferevent.h"
////#include "event2/buffer.h"
////#include "event2/listener.h"
////#include "event2/util.h"
////#include "event2/event_compat.h"
////#include "event2/event.h"
////#include "event2/keyvalq_struct.h"
////#include "event2/http.h"
////#include "event2/http_struct.h"
////#include "event2/http_compat.h"
////
////using namespace std;
////
////void timeout_cb(evutil_socket_t fd, short event, void* argc)
////{
////	printf("timeout\n");
////}
////
////int main()
////{
////	int port = 8888;
////
////	/*Database *database = Database::GetInstance();
////	std::string account = database->Register("wang", "fafs");
////	database->CreateTable(account);*/
////
////	WSADATA wsaData;
////	int result;
////
////	result = WSAStartup(MAKEWORD(2, 2), &wsaData);
////	if (result != 0)
////	{
////		std::cerr << "WSAStartup fail" << std::endl;
////		return -1;
////	}
////
////	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
////	if (fd == -1)
////	{
////		std::cerr << "socket fail" << std::endl;
////		return -1;
////	}
////
////	//地址可复用
////	int optval = 1;
////	result = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(int));
////
////	struct sockaddr_in local_addr;
////	memset(&local_addr, 0, sizeof(struct sockaddr_in));
////	local_addr.sin_family = AF_INET;
////	local_addr.sin_port = htons(port);
////	local_addr.sin_addr.s_addr = INADDR_ANY;
////	int ret = bind(fd, (struct sockaddr*)&local_addr, sizeof(struct sockaddr));
////	if (ret == -1)
////	{
////		std::cerr << "bind fail" << std::endl;
////		return -1;
////	}
////
////	ret = listen(fd, 10);
////	if (ret == -1)
////	{
////		std::cerr << "listen fail" << std::endl;
////		return -1;
////	}
////
////	char str[1000];
////	memset(str, 0, 1000);
////
////	struct event_base* base = event_init();
////	
////	timeval tv = { 1, 0 };
////	struct event* timeout_event = event_new(base, -1, 0, timeout_cb, nullptr);
////	event_add(timeout_event, &tv);
////	event_base_dispatch(base);
////
////	event_free(timeout_event);
////	event_base_free(base);
////	
////	cout << "Hello CMake." << endl;
////	return 0;
////}
//
//
////#define WIN32_LEAN_AND_MEAN
////#define _WINSOCK_DEPRECATED_NO_WARNINGS
////
////#include <windows.h>
////#include <WinSock2.h>
////#include <stdio.h>
////
////#pragma comment(lib, "ws2_32.lib")
////
////int main()
////{
////	// 启动Windows socket 2.x环境
////	WORD ver = MAKEWORD(2, 2);
////	WSADATA dat;
////	WSAStartup(ver, &dat);
////	//----------------
////
////	// --用Socket API建立简易TCP服务器
////	// 创建一个socket
////	SOCKET _sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
////	// 绑定用于接受客户端连接的网络端口
////	sockaddr_in _sin = {};
////	_sin.sin_family = AF_INET;
////	_sin.sin_port = htons(8888);
////	_sin.sin_addr.S_un.S_addr = INADDR_ANY;
////	if (SOCKET_ERROR == bind(_sock, (sockaddr*)&_sin, sizeof(_sin)))
////		printf("ERROR,绑定用于接受客户端连接的网络端口失败...\n");
////	else
////		printf("绑定端口成功...\n");
////
////	// 监听端口
////	if (SOCKET_ERROR == listen(_sock, 5))
////		printf("监听网络端口失败...\n");
////	else
////		printf("监听网络端口成功...\n");
////
////	// 接收客户端连接
////	sockaddr_in clientAddr = {};
////	int nAddrLen = sizeof(sockaddr_in);
////	SOCKET _cSock = INVALID_SOCKET;
////
////
////	// 向客户端发送一条数据
////	char msgBuf[] = "Hello, I'm Server.";
////	while (true) {
////		_cSock = accept(_sock, (sockaddr*)&clientAddr, &nAddrLen);
////		if (INVALID_SOCKET == _cSock)
////			printf("接受到无效客户端SOCKET...\n");
////		printf("新客户端加入:IP = %s\n", inet_ntoa(clientAddr.sin_addr));
////		send(_cSock, msgBuf, sizeof(msgBuf), 0);
////	}
////	closesocket(_sock);
////	WSACleanup();
////	return 0;
////}
//
