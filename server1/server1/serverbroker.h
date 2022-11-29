#ifndef SERVERBROKER_H
#define SERVERBROKER_H

#ifdef WIN32
#define FD_SETSIZE 1024
#include <winsock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#endif  //WIN32

#include <atomic>
#include <unordered_map>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <openssl/ssl.h>
#include <event2/event.h>

class Http;
class Database;
class Cryptogram;
class LOGGER;

struct UserMessage
{
	std::string token = "";
	std::string ip = "";
	std::string account = "";
	int visitNumber = 0;
	std::chrono::time_point<std::chrono::steady_clock> start = std::chrono::steady_clock::now();
	std::chrono::time_point<std::chrono::steady_clock> end = std::chrono::steady_clock::now();
};

class ServerBroker 
{
public:
	ServerBroker();
	~ServerBroker();

	//��ʼ���ÿͻ����ļ�����������������
	void Init(int sockfd, const sockaddr_in& address, SSL_CTX** ctx);

	//
	void SetEvent(struct event *event, void (*readfun)(evutil_socket_t, short, void*), void (*writefun)(evutil_socket_t, short, void*));

	//�ر���ͻ��˵�����
	void CloseConnection();

	//��ȡ�ͻ��˷��͹���������
	bool ReadData();

	//��ͻ��˷�������
	bool WriteData();


	
public:   //ȫ�ֱ���
	static fd_set m_fdWrite;												//windows��ʹ��select������Ҫд���ļ�������
	static fd_set m_fdRead;													//windows��ʹ��select������Ҫ�����ļ�������
	static fd_set m_fdException;											//windows��ʹ��select�����������ݵ��ļ�������
	static int m_epollFd;													//Linux��ʹ�� epoll �ļ���������
	static struct event_base* m_base;
	static std::atomic<int> m_userCount;									//ͳ�Ƶ�ǰ�û���������
	static std::unordered_map<std::string, UserMessage> m_accounts;			//���浱ǰ�ѵ�¼ token ��Ӧ���û���Ϣ
	static std::unordered_map<std::string, std::string> m_logAccounts;		//���浱ǰ�ѵ�¼���ʺźͶ�Ӧ�� token
	static std::unordered_map<std::string, std::chrono::time_point<std::chrono::steady_clock>> m_restrictIp;	//����Ƶ�����ʱ�����IP

private:
	//
	void ModeEvent(short event);

	//���û��ĵ�������з���
	bool Worker();					

	//�����û���get����
	bool ProcessGet();

	//�����û���post����
	bool ProcessPost();

	//�����û��ĵ�¼����
	bool Login();

	//�����û���ע������
	bool Register();

	//�����û��˳�ϵͳ
	bool Exit();

	//�����û��ϴ��ļ�������
	bool UpFile();

	//�����û��鿴�ļ�������
	bool DownFile();

	//�����û���ȡ���ϴ��ļ��б������
	bool AcquireFiles();

	//
	bool AccessRestrict(std::string& jwt);


private:
	Http* m_http = nullptr;					//http���ݴ������
	Database* m_database = nullptr;			//���ݿ��������
	Cryptogram* m_cryptogram = nullptr;		//���ݱ��ܶ���
	int m_socketFd;							//�ͻ����ļ�������
	sockaddr_in m_address;					//�洢�ͻ����׽�����Ϣ

	LOGGER *m_logger;
	SSL* m_ssl = nullptr;
	struct event* m_event = nullptr;
	void (*m_readfun)(evutil_socket_t, short, void*);
	void (*m_writefun)(evutil_socket_t, short, void*);
	
};
typedef std::shared_ptr<ServerBroker > ServerBrokerPtr;
#endif //SERVERBROKER_H