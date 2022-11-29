#include "plainhttp.h"
#include <string.h>
#include <iostream>
#include "define.h"

#ifdef WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#endif



PlainHttp::PlainHttp() : m_ssl{nullptr}, m_ctx{nullptr}, m_epollFd{-1}, m_socketFd{-1}, m_sendContent{0}, m_sendLength{0}
{
	curl_global_init(CURL_GLOBAL_ALL);
	/* SSL 库初始化*/
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	m_ctx = SSL_CTX_new(TLS_client_method());
	if (m_ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	// 双向验证
	// SSL_VERIFY_PEER---要求对证书进行认证，没有证书也会放行
	// SSL_VERIFY_FAIL_IF_NO_PEER_CERT---要求客户端需要提供证书，但验证发现单独使用没有证书也会放行
	SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	// 设置信任根证书
	if (SSL_CTX_load_verify_locations(m_ctx, CLIENT_CA_FILE, NULL) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	/* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
	if (SSL_CTX_use_certificate_file(m_ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	/* 载入用户私钥 */
	if (SSL_CTX_use_PrivateKey_file(m_ctx, CLIENT_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	/* 检查用户私钥是否正确 */
	if (!SSL_CTX_check_private_key(m_ctx)) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
}

PlainHttp::~PlainHttp()
{
	SSL_CTX_free(m_ctx);
	CloseLink(m_socketFd);
	if (m_sendContent != nullptr)
	{
		delete[] m_sendContent;
		m_sendContent = nullptr;
	}

	if (m_socketFd != -1)
	{
#ifdef WIN32
		closesocket(m_socketFd);
#else
		close(m_socketFd);
#endif

	}

	if (m_epollFd != -1)
	{
#ifndef WIN32
		close(m_socketFd);
#endif
	}
}

bool PlainHttp::SendPost(void)
{
	bool result = false;
	std::cout << "sendpost" << std::endl;
	if (!LinkServer(m_ip, m_port))
	{
		return result;
	}

	result = ConstructPost();
	if (!result)
	{
		return result;
	}

	result = WriteData();

	return result;
	
}

bool PlainHttp::SendGet(void)
{
	bool result = false;

	if (!LinkServer(m_ip, m_port))
	{
		return result;
	}

	result = ConstructGet();
	if (!result)
	{
		return result;
	}

	result = WriteData();

	return result;
}

bool PlainHttp::ConstructGet()
{
	std::string request = "GET " + m_url + " HTTP/1.1\r\n";
	for (auto& m : m_requestHeader)
	{
		request += m.first + ": " + m.second + "\r\n";
	}
	request += "Content-Length: 0\r\n\r\n";

	if (request == "")
	{
		return false;
	}

	m_sendLength = request.size();

	if (m_sendContent != nullptr)
	{
		delete[] m_sendContent;
		m_sendContent = nullptr;
	}

	m_sendContent = new char[m_sendLength];
	memset(m_sendContent, 0, m_sendLength);
	memcpy(m_sendContent, request.c_str(), m_sendLength);

	return true;
}

bool PlainHttp::ConstructPost()
{
	std::cout << "construct post" << std::endl;
	std::string request = "POST " + m_url + " HTTP/1.1\r\n";
	for (auto& m : m_requestHeader)
	{
		request += m.first + ": " + m.second + "\r\n";
	}

	if (m_requestHeader.count("Content-Length"))
	{
		request += "\r\n";
	}
	else
	{
		request += "Content-Length: " + std::to_string(m_contentLength) + "\r\n\r\n";
	}

	if (request == "")
	{
		return false;
	}

	m_sendLength = request.size();
	m_sendLength += m_contentLength;
	
	if (m_sendContent != nullptr)
	{
		delete[] m_sendContent;
		m_sendContent = nullptr;
	}

	m_sendContent = new char[m_sendLength];
	memset(m_sendContent, 0, m_sendLength);
	memcpy(m_sendContent, request.c_str(), request.size());
	memcpy(m_sendContent + request.size(), m_content, m_contentLength);

	return true;
}

void PlainHttp::SetNonblocking(int fd)
{
#ifdef WIN32

	unsigned long ul = 1;

	int ret = ioctlsocket(fd, FIONBIO, (unsigned long*)&ul);//设置成非阻塞模式。

	if (ret == SOCKET_ERROR)//设置失败。

	{
		std::cerr << "setting nonblock failed" << std::endl;
	}
#else

	int block = 1;
	int flag = fcntl(fd, F_GETFL);
	flag |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flag);
#endif
}

bool PlainHttp::LinkServer(std::string ip, int port)
{
	//std::cout << "linke server" << std::endl;
	bool result = false;

	if (ip == "" || port < 0 || port > 65535)
	{
		return result;
	}

#ifndef WIN32
	if (m_epollFd == -1)
	{
		m_epollFd = epoll_create(5);
	}
#endif

	if (m_socketFd != -1)
	{
		CloseLink(m_socketFd);
	}

	m_socketFd = socket(PF_INET, SOCK_STREAM, 0);
	if (m_socketFd == -1)
	{
		return false;
	}

#ifdef WIN32

#else

	epoll_event event;
	event.data.fd = m_socketFd;
	event.events = EPOLLIN | EPOLLHUP;
	epoll_ctl(m_epollFd, EPOLL_CTL_ADD, m_socketFd, &event);
#endif

	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr.s_addr);
	int ret = ::connect(m_socketFd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if (ret == -1)
	{
		//std::cout << "linke error" << std::endl;
		return false;
	}

	SetNonblocking(m_socketFd);
	m_ssl = SSL_new(m_ctx);
	if (m_ssl != nullptr)
	{
		std::cout << "create ssl success" << std::endl;
	}
	SSL_set_fd(m_ssl, m_socketFd);
	SSL_set_connect_state(m_ssl);
	do {
		ret = SSL_do_handshake(m_ssl);
	} while (ret != 1);
	std::cout << "ssl connect success" << std::endl;

	// SSL_get_verify_result()是重点，SSL_CTX_set_verify()只是配置启不启用并没有执行认证，调用该函数才会真证进行证书认证
	// 如果验证不通过，那么程序抛出异常中止连接
	if (SSL_get_verify_result(m_ssl) == X509_V_OK) {
		std::cout << "证书验证通过" << std::endl;
	}
	else
	{
		std::cout << "证书验证失败" << std::endl;
	}

	return true;
}

bool PlainHttp::WriteData()
{
	std::cout << m_socketFd << "  " << m_sendLength << std::endl;
	if (m_socketFd == -1 || m_sendLength <= 0)
	{
		return false;
	}

	int writeindex = 0;
	int writelen = 0;
	while (writeindex != m_sendLength) {
		writelen = SSL_write(m_ssl, m_sendContent + writeindex, m_sendLength - writeindex);
		std::cout << "writelen: " << writelen << std::endl;
		if (writelen > 0)
		{
			writeindex += writelen;
		}
		else
		{
			int ret = SSL_get_error(m_ssl, writelen);
			switch (ret)
			{
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				continue;
				break;
			case SSL_ERROR_ZERO_RETURN:
				CloseLink(m_socketFd);
				return false;
				break;
			default:
				CloseLink(m_socketFd);
				return false;
				;
			}
		}
	}
	std::cout << "send success" << std::endl;
	return true;
}

int PlainHttp::ReadData(char* outData, int readLength, bool flag)
{
	std::cout << "read data" << readLength << std::endl;
	if (m_socketFd == -1)
	{
		return -1;
	}
	if(flag)
	{ 
#ifdef WIN32
	struct timeval time_val;
	while (1)
	{
		time_val.tv_sec = 10;
		time_val.tv_usec = 0;
		FD_ZERO(&fdr);
		FD_SET(m_socketFd, &fdr);
		select(m_socketFd + 1, &fdr, nullptr, nullptr, &time_val);
		if (FD_ISSET(m_socketFd, &fdr))
		{
			break;
		}
	}
#else
		if (m_epollFd == -1)
		{
			return -1;
		}
		epoll_event events[10];
		epoll_wait(m_epollFd, events, 10, -1);
#endif
		}

	//std::cout << "init read data" << std::endl;
	int readindex = 0;
	int readlen = 0;
	while (readindex != readLength)
	{
		//std::cout << "readLength" << readLength - readindex << std::endl;
		readlen = SSL_read(m_ssl, outData + readindex, readLength - readindex);
		//std::cout << "readlen:" << readlen << std::endl;
		if (readlen > 0)
		{
			readindex += readlen;
		}
		else
		{
			int iErrCode = SSL_get_error(m_ssl, readlen);
			switch (iErrCode)
			{
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				if (readindex > 0)
				{
					return readindex;
				}
				//std::cout << "The operation did not complete; the same TLS/SSL I/O function should be called again later." << std::endl;
				continue;
				break;
			case SSL_ERROR_ZERO_RETURN:
				//std::cout << "ssl channel(fd %d) closed by peer." << std::endl;
				CloseLink(m_socketFd);
				return -1;
				break;
			case SSL_ERROR_SYSCALL:
				//std::cout << "Some non-recoverable I/O error occurred. The OpenSSL error queue may contain more information on the error. "
					//"For socket I/O on Unix systems, consult errno %d for details." << std::endl;
				CloseLink(m_socketFd);
				return -1;
				break;
			default:
				//std::cout << "SSL_read() error code %d, see SSL_get_error() manual for error code detail." << std::endl;
				CloseLink(m_socketFd);
				return -1;
				;
			}
		}
	}
	//std::cout << "readindex" << readindex << std::endl;
	return readindex;
}

void PlainHttp::CloseLink(int socketFd)
{
	if (socketFd != -1)
	{
		SSL_shutdown(m_ssl);
		SSL_free(m_ssl);
#ifdef WIN32
		closesocket(socketFd);
#else
		close(socketFd);
#endif // WIN32

		socketFd = -1;
	}
}

bool PlainHttp::ModeEpollEvent(int epollfd, int fd, int type)
{
#ifndef WIN32
	epoll_event event;
	event.events = type;
	event.data.fd = fd;
	int ret = epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event);

	if (ret == 0)
	{
		return true;
	}
#endif
	return false;
}
