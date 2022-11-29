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
    /*�����ͻ�������ʱ����״̬����״̬
    * CHECK_STATE_REQUESTLINE:��ǰ���ڷ���������
    * CHECK_STATE_HEADER:��ǰ���ڷ���ͷ���ֶ�
    * CHECK_STATE_CONTENT:��ǰ���ڽ���������
    */
    enum CHECK_STATE { CHECK_STATE_REQUESTLINE = 0, CHECK_STATE_HEADER, CHECK_STATE_CONTENT };

    /*��״̬�������ֿ���״̬�����еĶ�ȡ״̬���ֱ��ʾ
    * 1.��ȡ��һ���������� 2.�г��� 3.���������Ҳ�����
    */
    enum LINE_STATUS { LINE_ENTIRE = 0, LINE_ERROR, LINE_OPEN };

    /*����������HTTP����Ŀ��ܽ�������Ľ����Ľ��
    * NOENTIRE_REQUEST          :  ������������Ҫ������ȡ�ͻ�����
    * ENTIRE_REQUEST            :  ��ʾ�����һ�������Ŀͻ�����
    * SYNTAXERERROR_REQUEST     :  ��ʾ�ͻ������﷨����
    * NORESOURCE_REQUEST        :  ��ʾ������û����Դ
    * FORBIDDENVISIT_REQUEST    :  ��ʾ�ͻ�����Դû���㹻�ķ���Ȩ��
    * FILE_REQUEST              :  �ļ����󣬻�ȡ�ļ��ɹ�
    * INTERNAL_ERROR            :  ��ʾ�������ڲ�����
    * CLOSED_CONNECTION         :  ��ʾ�ͻ����Ѿ��ر�������
    */
    enum HTTP_CODE {
        NOENTIRE_REQUEST, ENTIRE_REQUEST, SYNTAXERERROR_REQUEST, NORESOURCE_REQUEST,
        FORBIDDENVISIT_REQUEST, FILE_REQUEST, INTERNAL_ERROR, CLOSED_CONNECTION
    };

public:
    Http();
    ~Http();

    //����Ӧ����
    bool SendReply(void);   

    //��һЩ��ʼ������
    void Init(int sockfd, const sockaddr_in& address, SSL** ssl);

    //����Ӧ��ͷ
    bool SetReplyHeader(std::string key, std::string value);

    //ͨ��key��ȡ����ͷ��ֵ
    std::string GetRequestHeader(std::string key);

    //����Ӧ�����ݼ��䳤��
    bool SetReplyContent(const char* content, int len);

    //��ȡ������
    char* GetRequestContent(void);

    //��ȡӦ����
    HTTP_CODE AcquireRequest(void);

    //ͨ��key��ȡӦ��ͷ
    std::string GetReplyHeader(std::string key);

    //��ȡӦ����
    char* GetReplyContent(void);

    //��ȡӦ����ĳ���
    int GetReplyContentLen(void);

    //��ȡ������ĳ���
    int GetRequestContentLen(void);

    //�������
    void ClearRequest(void);

    //���Ӧ������
    void ClearReply(void);

    //��ȡ���󷽷�
    std::string GetMethod(void);

    //��ȡ����url
    std::string GetUrl(void);

    //����Ӧ����״̬��
    bool SetStateCode(int statecode);


private:
    //�Լ�ͨ��socket���������Լ���ȡ������http����

    //����Ӧ����
    bool ConstructReply();

    //����Ӧ������
    std::string ConstructHeaderLine();

    //����Ӧ��ͷ
    std::string ConstructHeaders(std::string statueLine);
    
    //����Ӧ����
    bool ConstructContent(std::string headers);

    //���׽�������д���ݣ������ͻ���
    bool WriteData(int socketFd, const char* data, int writeLength);

    //���׽������������
    int ReadData(int socketFd, char* outData, int readLength);

    //�رպͷ�����������
    void CloseLink(int socketFd);

    //����epoll�ļ�������
    bool ModeEpollEvent(int epollfd, int fd, int type);


    //����һ���Ƿ�Ϸ�
    LINE_STATUS ParseLine();

    //�ӻ����������ȡһ��
    char* GetLine();

    //����Ӧ����
    HTTP_CODE ParseRequest();

    //����Ӧ��������
    HTTP_CODE ParseRequestFirstLine(std::string content);

    //����Ӧ����ͷ
    HTTP_CODE ParseHeader(std::string content);

    //����Ӧ������
    HTTP_CODE ParseContent();


    //��ȡ��һ���ո����ڵ�λ�ã���û���򷵻�-1���򷵻ؿո��λ��
    int SearchSpace(std::string& content, int start);

    //��ȡ��һ���ַ����ڵ�λ�ã���û���򷵻�-1���򷵻��ַ���λ��
    int SearchCharacter(std::string& content, int start);

    //��ʼ��״̬��Ͷ�Ӧ��Ӣ������
    void InitDescription(std::unordered_map<int, std::string>& description);

private:
    std::unordered_map<std::string, std::string> m_requestHeader;   //��ſͻ�������ͷ��
    std::unordered_map<std::string, std::string> m_replyHeader;     //���Ӧ��ͻ���ͷ����Ϣ
    std::unordered_map<int, std::string> m_description;             //���״̬�뼰���Ӧ������
    std::string m_url;                                              //�������url
    char* m_requestContent = nullptr;                               //��ſͻ��˷��͵�����
    int m_requestContentLength;                                     //��ſͻ��˷������ݵĳ���
    char* m_replyContent = nullptr;                                 //���Ӧ��ͻ�������
    int m_replyContentLength;                                       //���Ӧ��ͻ������ݵĳ���
    int m_replyLength;                                              //���Ӧ���ĵ���������
    int m_socketFd;                                                 //��ſͻ����׽����ļ�������
    sockaddr_in m_address;                                          //��ſͻ��˵�ַ��Ϣ


    std::string m_requestVersion;                                   //���http����汾
    std::string m_httpVersion;                                      //���httpӦ��汾
    int m_stateCode;                                                //���Ӧ��״̬��
    std::string m_stateDescription;                                 //���״̬���Ӧ������
    std::string m_requestMethod;                                    //�������ķ���

    int m_bufferSize;                                               //�������ռ�
    char* m_tmpBuffer = nullptr;                                    //��Ż�������С
    int m_checkIndex;                                               //��Ž���Ӧ������λ��
    int m_readLength;                                               //���Ӧ�������ȡ����
    int m_readIndex;                                                //����Ѿ��ӻ�������ȡ�����ݳ���
    int m_checkState;                                               //��ŵ�ǰ����״̬

    char* m_reply = nullptr;                                        //Ӧ����
    SSL* m_ssl = nullptr;

};

#endif // HTTP_H