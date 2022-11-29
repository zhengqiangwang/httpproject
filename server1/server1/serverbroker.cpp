#include "serverbroker.h"
#include "http.h"
#include <iostream>
#include "database.h"
#include <nlohmann/json.hpp>
#include <boost/filesystem.hpp>
#include "cryptogram.h"
#include "logger.h"
#include "define.h"



using json = nlohmann::json;

fd_set ServerBroker::m_fdWrite = { 0 };
fd_set ServerBroker::m_fdRead = { 0 };
fd_set ServerBroker::m_fdException = { 0 };
int ServerBroker::m_epollFd = -1;
struct event_base* ServerBroker::m_base = nullptr;
std::atomic<int> ServerBroker::m_userCount = 0;
std::unordered_map<std::string, UserMessage> ServerBroker::m_accounts;
std::unordered_map<std::string, std::string> ServerBroker::m_logAccounts;
std::unordered_map<std::string, std::chrono::time_point<std::chrono::steady_clock>> ServerBroker::m_restrictIp;

void SetNonblocking(int fd)
{
#ifdef WIN32

	unsigned long ul = 1;

	int ret = ioctlsocket(fd, FIONBIO, (unsigned long*)&ul);//设置成非阻塞模式。

	if (ret == SOCKET_ERROR)//设置失败。

	{
		//std::cerr << "setting nonblock failed" << std::endl;
	}
#else

	int block = 1;
	int flag = fcntl(fd, F_GETFL);
	flag |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flag);
#endif
}

void AddSelectFd(fd_set &selectFd, int fd)
{
	std::cout << "addselecfd:" << fd << std::endl;
#ifdef WIN32
	if (!FD_ISSET(fd, &selectFd))
	{
		FD_SET(fd, &selectFd);
	}
	if (FD_ISSET(fd, &selectFd))
	{
		std::cout << "select setting success" << std::endl;
	}
#endif
}

void RemoveSelectFd(fd_set &selectFd, int fd)
{
#ifdef WIN32
	if (FD_ISSET(fd, &selectFd))
	{
		FD_CLR(fd, &selectFd);
	}
#endif
}

void Addfd(int epollfd, int fd, bool one_shot) {
#ifndef WIN32
	epoll_event event;
	event.data.fd = fd;
	event.events = EPOLLIN | EPOLLHUP;

	if (one_shot) {
		event.events |= EPOLLONESHOT;
	}
	epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
	SetNonblocking(fd);
#endif 
}

void Removefd(int epollfd, int fd) {
#ifndef WIN32
	epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, nullptr);
	close(fd);
#endif //WIN32
}

void Modefd(int epollfd, int fd, int ev) {
#ifndef WIN32
	epoll_event event;
	event.data.fd = fd;
	event.events = ev | EPOLLONESHOT | EPOLLHUP;

	epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event);
#endif //WIN32
}

ServerBroker::ServerBroker(): m_http{nullptr}, m_socketFd{-1}, m_database{nullptr}, m_cryptogram{nullptr}, m_address{0}, m_logger{nullptr}, m_ssl{nullptr}
{
}

ServerBroker::~ServerBroker()
{
	m_logger->WriteLog(LOG_LEVEL_INFO, __FILE__, __FUNCTION__, __LINE__, (char*)"enter destroy");
	if (m_http)
	{
		delete m_http;
	}

	if (m_cryptogram)
	{
		delete m_cryptogram;
	}

	if (m_ssl)
	{
		SSL_free(m_ssl);
		m_ssl = nullptr;
	}
	CloseConnection();
}

void ServerBroker::Init(int sockfd, const sockaddr_in& address, SSL_CTX **ctx)
{
	std::cout << this << std::endl;
	m_socketFd = sockfd;
	m_address = address;
	if(m_http == nullptr)
		m_http = new Http;
	m_database = Database::GetInstance();
	if(m_cryptogram == nullptr)
		m_cryptogram = new Cryptogram;
	m_logger = LOGGER::GetInstance();
	
	SetNonblocking(m_socketFd);

	if (m_ssl != nullptr)
	{
		SSL_free(m_ssl);
		m_ssl = nullptr;
		std::cout << "free ssl:" << m_ssl << std::endl;
	}
	m_ssl = SSL_new(*ctx);
	if (m_ssl == nullptr)
	{
		std::cout << "m_ssl new fail" << std::endl;
	}
	std::cout << "m_ssl:" << m_ssl << std::endl;
	SSL_set_fd(m_ssl, m_socketFd);
	SSL_set_accept_state(m_ssl);
	int ret = 0;
	do {
		ret = SSL_do_handshake(m_ssl);	//由于使用了非阻塞io所以使用这个接口
		std::cout << "hand shake ret:" << ret << std::endl;
	} while (ret != 1);
	
	
	// SSL_get_verify_result()是重点，SSL_CTX_set_verify()只是配置启不启用并没有执行认证，调用该函数才会真证进行证书认证
	// 如果验证不通过，那么程序抛出异常中止连接
	if (SSL_get_verify_result(m_ssl) == X509_V_OK) {
		m_logger->WriteLog(LOG_LEVEL_INFO, __FILE__, __FUNCTION__, __LINE__, (char *)"证书验证通过");
	}
	else
	{
		m_logger->WriteLog(LOG_LEVEL_INFO, __FILE__, __FUNCTION__, __LINE__, (char*)"证书验证失败");
	}

	std::cout << "m_ssl" << m_ssl << std::endl;
	m_http->Init(m_socketFd, m_address, &m_ssl);
	m_cryptogram->Init();

#ifdef WIN32
	AddSelectFd(m_fdRead, m_socketFd);
#else
	Addfd(m_epollFd, m_socketFd, true);
#endif //WIN32
	m_userCount++;
}

void ServerBroker::SetEvent(struct event* event, void (*readfun)(evutil_socket_t, short, void*), void (*writefun)(evutil_socket_t, short, void*))
{
	m_event = event;
	m_readfun = readfun;
	m_writefun = writefun;
}

void ServerBroker::CloseConnection()
{
	m_logger->WriteLog(LOG_LEVEL_INFO, __FILE__, __FUNCTION__, __LINE__, (char*)"enter closeconnection");
	if (m_socketFd != -1)
	{
		m_logger->WriteLog(LOG_LEVEL_INFO, __FILE__, __FUNCTION__, __LINE__, (char*)"close m_socketFd : %d", m_socketFd);
		m_userCount--;
#ifdef WIN32
		RemoveSelectFd(m_fdWrite, m_socketFd);
		RemoveSelectFd(m_fdRead, m_socketFd);
		RemoveSelectFd(m_fdException, m_socketFd);
		
		if (m_ssl)
		{
			SSL_shutdown(m_ssl);
			SSL_clear(m_ssl);
		}
		
		closesocket(m_socketFd);
#else
		if (m_ssl)
		{
			SSL_shutdown(m_ssl);
			SSL_clear(m_ssl);
		}

		Removefd(m_epollFd, m_socketFd);
#endif
		m_socketFd = -1;
	}
}

bool ServerBroker::ReadData()
{
	std::cout << "read this:" << this << std::endl;
	Http::HTTP_CODE result;
	result = m_http->AcquireRequest();
	
	if (result != Http::ENTIRE_REQUEST)
	{
		CloseConnection();
		event_free(m_event);
		return result;
	}
	else
	{
		Worker();
	}
	AddSelectFd(m_fdRead, m_socketFd);
	return true;
}

bool ServerBroker::WriteData()
{
	std::cout << "write this:" << this << std::endl;
	//std::cout << "write data ------------------" << std::endl;
	if (m_http->SendReply())
	{
		ModeEvent(EV_READ);
		AddSelectFd(m_fdRead, m_socketFd);
	}

	
	return true;
}

void ServerBroker::ModeEvent(short event)
{
	if (event & EV_READ)
	{
		event_assign(m_event, event_get_base(m_event), event_get_fd(m_event), EV_READ, m_readfun, event_get_callback_arg(m_event));
	}
	if (event & EV_WRITE)
	{
		event_assign(m_event, event_get_base(m_event), event_get_fd(m_event), EV_WRITE|EV_READ, m_writefun, event_get_callback_arg(m_event));
	}
	event_add(m_event, nullptr);
	short r = event_get_events(m_event);
	if (r & EV_READ)
	{
		std::cout << "serverbroker EV_READ" << std::endl;
	}
	if (r & EV_WRITE)
	{
	    std::cout << "serverbroker EV_WRITE" << std::endl;
	}
}

bool ServerBroker::Worker()
{
	m_logger->WriteLog(LOG_LEVEL_INFO, __FILE__, __FUNCTION__, __LINE__, (char *)"enter worker");
	std::string method = "";
	method = m_http->GetMethod();
	m_logger->WriteLog(LOG_LEVEL_INFO, __FILE__, __FUNCTION__, __LINE__, method.data());
	if (method == "GET")
	{
		std::cout << "Get request" << std::endl;
		std::cout << m_http->GetUrl() << std::endl;
		ProcessGet();
	}
	else if (method == "POST")
	{
		std::cout << "Post request" << std::endl;
		std::cout << m_http->GetUrl() << std::endl;
		ProcessPost();
	}
	else
	{
		std::cout << "other request" << std::endl;
	}

	return true;
}

bool ServerBroker::ProcessGet()
{
	
	std::string url = "";
	url = m_http->GetUrl();
	std::cout << "Process get request" << ";url:"<<url << std::endl;
	if (url.find("/files?") != std::string::npos)
	{
		AcquireFiles();
	}
	else
	{
		DownFile();
	}
	return true;
}

bool ServerBroker::ProcessPost()
{
	std::cout << "Process post request" << std::endl;
	std::string url = m_http->GetUrl();
	//std::cout << url << std::endl;
	m_logger->WriteLog(LOG_LEVEL_INFO, __FILE__, __FUNCTION__, __LINE__, (char*)"url: %s", url);
	if (url.find("Login") != std::string::npos)
	{
		Login();
	}
	else if(url.find("Register") != std::string::npos)
	{
		
		Register();
	}
	else if (url.find("Exit") != std::string::npos)
	{
		Exit();
	}
	else
	{
		UpFile();
	}
	return true;
}

bool ServerBroker::Login()
{
	m_logger->WriteLog(LOG_LEVEL_INFO, __FILE__, __FUNCTION__, __LINE__, (char*)"enter log");
	std::string content = m_http->GetRequestContent();

	json j3 = json::parse(content);

	Database* database = Database::GetInstance();

	if (database->Longin(j3["account"], j3["password"]))
	{
		std::cout << "Login success" << std::endl;
		std::string password = j3["password"];
		json state;

		std::string jwt = "";
		std::string account = j3["account"];

		char pip[17];
		memset(pip, 0, 17);
		inet_ntop(AF_INET, &m_address.sin_addr.s_addr, pip, 17);
		std::string ip = pip;
		
		std::cout<<"ip:" << ip <<","<< ip.size()<<","<<account <<","<<account.size()<<",fd:"<<m_socketFd << "----------------------------------------------------------------" << std::endl;
		jwt = m_cryptogram->CreateJwt(account, ip);
		std::cout << "compare:" << m_cryptogram->VertifyJwt(jwt, account, ip) << "  ;" << jwt << std::endl;
		if (jwt != "")
		{
			if (m_accounts.count(jwt))
			{
				UserMessage usermessage = m_accounts[jwt];
				usermessage.start = std::chrono::steady_clock::now();
				usermessage.end = std::chrono::steady_clock::now();
				usermessage.visitNumber = 0;
				m_accounts[jwt] = usermessage;
				state["status"] = "alreadylogin";
			}
			else
			{
				UserMessage usermessage;
				usermessage.token = jwt;
				usermessage.ip = ip;
				usermessage.end = std::chrono::steady_clock::now();
				usermessage.account = j3["account"];
				usermessage.visitNumber++;
	
				if (m_logAccounts.count(account))
				{
					
					m_accounts.erase(m_accounts.find(m_logAccounts[account]));
					//给先登录的设备发一条退出登录的消息未处理
					m_logAccounts[account] = jwt;
					state["status"] = "otherdevicelogin";
				}
				else
				{
					
					state["status"] = "success";
					m_logAccounts[account] = jwt;
				}
				m_accounts[jwt] = usermessage;
			}
		}
		else
		{
			state["status"] = "fail";
		}

		std::string s = state.dump();

		char* recontent = new char[s.size() + 1];
		memset(recontent, 0, s.size() + 1);
		memcpy(recontent, s.data(), s.size());
		printf("reply: %s\n", recontent);
		
		m_http->ClearReply();
		m_http->SetReplyHeader("Set-Cookie",jwt);
		m_http->SetReplyContent(recontent, s.size());
		delete[] recontent;
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
		m_http->ClearReply();
		m_http->SetReplyContent(recontent, s.size());
		delete[] recontent;
	}
	
	ModeEvent(EV_WRITE);
#ifdef WIN32
	AddSelectFd(m_fdWrite, m_socketFd);
#else 
	Modefd(m_epollFd, m_socketFd, EPOLLOUT);
#endif
	return true;
}

bool ServerBroker::Register()
{
	std::string content = m_http->GetRequestContent();
	content = content.substr(0, m_http->GetRequestContentLen());
	json j3 = json::parse(content);

	std::string account = m_database->Register(j3["name"], j3["password"]);
	if (account != "")
	{
		m_database->CreateTable(account);

		std::string path = WORKINGPATH;
		path += "/files/user" + account;
		if (!boost::filesystem::is_directory(path))
		{
			std::cout << "begin create path: " << path << std::endl;
			if (!boost::filesystem::create_directories(path))
			{
				std::cout << "create_directories failed: " << path << std::endl;
				return -1;
			}
		}
		else
		{
			std::cout << path << " aleardy exist" << std::endl;
		}
		std::cout << "Register success" << std::endl;
		json state;
		state["account"] = account;
		std::string s = state.dump();

		char* recontent = new char[s.size() + 1];
		memset(recontent, 0, s.size() + 1);
		memcpy(recontent, s.data(), s.size());
		printf("reply: %s\n", recontent);
		m_http->ClearReply();
		m_http->SetReplyContent(recontent, s.size());
		delete[] recontent;
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
		m_http->ClearReply();
		m_http->SetReplyContent(recontent, s.size());
		delete[] recontent;
	}

	ModeEvent(EV_WRITE);
#ifdef WIN32
	AddSelectFd(m_fdWrite, m_socketFd);
#else 
	Modefd(m_epollFd, m_socketFd, EPOLLOUT);
#endif
	return true;
}

bool ServerBroker::Exit()
{
	std::cout << "user is log out" << std::endl;
	std::string cookie = "";
	cookie = m_http->GetRequestHeader("Set-Cookie");
	if (!m_accounts.count(cookie))
	{
		std::cout << "user is not login" << std::endl;
		m_http->SetStateCode(401);
}
	else
	{
		if (!AccessRestrict(cookie))
		{
			m_restrictIp.emplace(m_accounts[cookie].ip, std::chrono::steady_clock::now());
			CloseConnection();
			return false;
		}
		else
		{
			char pip[17];
			memset(pip, 0, 17);
			inet_ntop(AF_INET, &m_address.sin_addr.s_addr, pip, 17);
			std::string ip = pip;
			UserMessage usermessage = m_accounts[cookie];
			std::string account = usermessage.account;
			std::string token = usermessage.token;

			if (m_cryptogram->VertifyJwt(token, account, ip) == false)
			{
				std::cout << "user is not login" << std::endl;
				m_http->SetStateCode(401);
			}
			else
			{
				std::cout << "user is log out" << std::endl;
				json state;

				m_accounts.erase(m_accounts.find(cookie));
				m_logAccounts.erase(m_logAccounts.find(account));

				state["status"] = "success";

				std::string s = state.dump();

				char* recontent = new char[s.size() + 1];
				memset(recontent, 0, s.size() + 1);
				memcpy(recontent, s.data(), s.size());
				printf("reply: %s\n", recontent);

				m_http->ClearReply();
				m_http->SetReplyContent(recontent, s.size());
				delete[] recontent;
			}
		}
	}

	ModeEvent(EV_WRITE);
#ifdef WIN32
	AddSelectFd(m_fdWrite, m_socketFd);
#else 
	Modefd(m_epollFd, m_socketFd, EPOLLOUT);
#endif
	return true;
}

bool ServerBroker::UpFile()
{
	std::string cookie = "";
	std::string url = "";
	char* contentsrc = nullptr;
	int contentlen = 0;
	cookie = m_http->GetRequestHeader("Set-Cookie");
	if (!m_accounts.count(cookie))
	{
		std::cout << "user is not login" << std::endl;
		m_http->SetStateCode(401);
	}
	else
	{
		if (!AccessRestrict(cookie))
		{
			m_restrictIp.emplace(m_accounts[cookie].ip, std::chrono::steady_clock::now());
			CloseConnection();
			return false;
		}
		else
		{
			char pip[17];
			memset(pip, 0, 17);
			inet_ntop(AF_INET, &m_address.sin_addr.s_addr, pip, 17);
			std::string ip = pip;
			UserMessage usermessage = m_accounts[cookie];
			std::string account = usermessage.account;
			std::string token = usermessage.token;

			if (m_cryptogram->VertifyJwt(token, account, ip) == false)
			{
				std::cout << "user is not login" << std::endl;
				m_http->SetStateCode(401);
			}
			else
			{


				url = m_http->GetUrl();
				contentsrc = m_http->GetRequestContent();
				contentlen = m_http->GetRequestContentLen();

				char* content = new char[contentlen + 1];
				memset(content, 0, contentlen + 1);
				memcpy(content, contentsrc, contentlen);

				std::string subp = m_database->AddImage(account, url, std::to_string(contentlen));

				std::cout << "user is login" << std::endl;
				account = "/files/user" + account;
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
					m_http->SetStateCode(406);
				}
				else
				{
					subp = "/" + subp + ".txt";
					strncpy(savepath + len, subp.data(), subp.size());
					FILE* fp;
					std::cout << savepath << std::endl;
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
						printf("open save file fail");
						m_http->SetStateCode(406);
					}
					else
					{
						int l = fwrite(encode, 1, length, fp1);
						memset(encode, 0, length);
						fclose(fp1);
						std::cout << "input fp1 " << l << " size." << std::endl;
					}
					free(encode);
				}

				delete[] savepath;
				delete[]  content;
			}
		}
	}

	ModeEvent(EV_WRITE);
#ifdef WIN32
	AddSelectFd(m_fdWrite, m_socketFd);
#else 
	Modefd(m_epollFd, m_socketFd, EPOLLOUT);
#endif
	return true;
}

bool ServerBroker::DownFile()
{
	std::string cookie = "";
	std::string url = "";
	cookie = m_http->GetRequestHeader("Set-Cookie");
	if (!m_accounts.count(cookie))
	{
		std::cout << "user is not login" << std::endl;
		m_http->SetStateCode(401);
	}
	else
	{
		if (!AccessRestrict(cookie))
		{
			m_restrictIp.emplace(m_accounts[cookie].ip, std::chrono::steady_clock::now());
			CloseConnection();
			return false;
		}
		else
		{
			char pip[17];
			memset(pip, 0, 17);
			inet_ntop(AF_INET, &m_address.sin_addr.s_addr, pip, 17);
			std::string ip = pip;
			UserMessage usermessage = m_accounts[cookie];
			std::string account = usermessage.account;
			std::string token = usermessage.token;
			if (m_cryptogram->VertifyJwt(token, account, ip) == false)
			{
				std::cout << "user is not login" << std::endl;
				m_http->SetStateCode(401);
			}
			else
			{
				std::cout << "user is login" << std::endl;

				url = m_http->GetUrl();
				std::string path = m_database->QueryRoute(account, url);
				std::cout << "query path:" << path << std::endl;
				if (path != "")
				{
					path = "/files/user" + account + "/" + path + ".txt";
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

						char* deba = m_cryptogram->AesDecode(content, filestat.st_size);
						std::string de = m_cryptogram->Base64Decode(deba);

						int filelen = std::atoi(m_database->QueryLength(account, url).c_str());
						std::cout << "file len:" << filelen << std::endl;

						bool result = false;
						m_http->ClearReply();
						result = m_http->SetReplyContent(de.c_str(), filelen);
						if (result)
						{
							std::cout << "setting file content success" << std::endl;
						}
						delete[] deba;
						delete[] content;
						delete[] savepath;
					}
				}
				else
				{
					std::cout << "require image route failed" << std::endl;
					m_http->SetStateCode(406);
				}

			}
		}
	}

	ModeEvent(EV_WRITE);
#ifdef WIN32
	AddSelectFd(m_fdWrite, m_socketFd);
#else 
	Modefd(m_epollFd, m_socketFd, EPOLLOUT);
#endif
	return true;
}

bool ServerBroker::AcquireFiles()
{
	std::cout << "Acquire file pathe" << std::endl;
	std::string cookie = "";
	std::string url = "";
	
	cookie = m_http->GetRequestHeader("Set-Cookie");
	if (!m_accounts.count(cookie))
	{
		std::cout << "cookie error" << std::endl;
		m_http->SetStateCode(401);
	}
	else
	{
		if (!AccessRestrict(cookie))
		{
			m_restrictIp.emplace(m_accounts[cookie].ip, std::chrono::steady_clock::now());
			CloseConnection();
			return false;
		}
		else
		{ 
			char pip[17];
			memset(pip, 0, 17);
			inet_ntop(AF_INET, &m_address.sin_addr.s_addr, pip, 17);
			std::string ip = pip;
			UserMessage usermessage = m_accounts[cookie];
			std::string account = usermessage.account;
			std::string token = cookie;
			std::cout << "ip" << ip << " ,account:" << account<<" ,compare:"<<(token == usermessage.token) << std::endl;
			if (m_cryptogram->VertifyJwt(token, account, ip) == false)
			{
				std::cout << "user is not login" << std::endl;
				m_http->SetStateCode(401);
			}
			else
			{
				std::cout << "user is login" << std::endl;
				std::cout << account << std::endl;
				std::vector<std::string> path;
				if (m_database->QueryImage(account, path))
				{
					json pathes;
					pathes["paths"] = path;
					std::string s = pathes.dump();
					char* content = new char[s.size() + 1];
					memset(content, 0, s.size() + 1);
					memcpy(content, s.data(), s.size());
					m_http->ClearReply();
					m_http->SetReplyContent(content, s.size());
					delete[] content;
					struct evbuffer* evb = nullptr;
				}
				else
				{
					std::cerr << "acquire file list fail" << std::endl;
					m_http->SetStateCode(406);
				}
			}
		}
	}

	ModeEvent(EV_WRITE);
#ifdef WIN32
	AddSelectFd(m_fdWrite, m_socketFd);
#else 
	Modefd(m_epollFd, m_socketFd, EPOLLOUT);
#endif
	return true;
}

bool ServerBroker::AccessRestrict(std::string &jwt)
{
	UserMessage &usermessage = m_accounts[jwt];
	int second = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - std::chrono::duration_cast<std::chrono::seconds>(usermessage.start.time_since_epoch()).count();
	if (second < INTERVAL && usermessage.visitNumber > ACCESSNUMBER)
	{
		return false;
	}
	if (second > INTERVAL)
	{
		usermessage.start = std::chrono::steady_clock::now();
		usermessage.end = std::chrono::steady_clock::now();
		usermessage.visitNumber = 0;
	}
	else
	{
		usermessage.end = std::chrono::steady_clock::now();
		usermessage.visitNumber++;
	}
	
	return true;
}