#pragma once
#ifndef HTTP_H
#define HTTP_H

#ifdef WIN32
#include <WinSock2.h>
#endif

#include <string>
#include <unordered_map>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

class Http
{
public:
    Http();
    virtual ~Http();

    //����post����
    virtual bool SendPost(void);

    //����get����
    virtual bool SendGet(void);

    //���÷�����ip��ַ
    bool SetIpaddress(std::string ip);

    //���÷���˼����˿�
    bool SetPort(int port);

    //��������ͷ
    bool SetRequestHeader(std::string key, std::string value);

    //ͨ��key��ȡ����ͷ��ֵ
    std::string GetRequestHeader(std::string key);

    //���������弰�䳤��
    bool SetRequestContent(const char* content, int len);

    //��ȡ������
    char* GetRequestContent(void);

    //��������url
    bool SetUrl(const std::string url);

    //��ȡӦ����
    bool AcquireReply(void);

    //ͨ��key��ȡӦ��ͷ
    std::string GetReplyHeader(std::string key);
    
    //��ȡӦ����
    char* GetReplyContent(void);

    //��ȡӦ����ĳ���
    int GetReplyContentLen(void);

    //�������
    void ClearRequest();

    //���Ӧ������
    void ClearReply();

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

protected:
    //
    virtual bool WriteData();

    //
    virtual int ReadData(char* outData, int readLength, bool flag);

private:
    //���IP��ַ�Ƿ���Ч
    bool CheckIPAddrIsVaild(std::string str);

    //����һ���Ƿ�Ϸ�
    LINE_STATUS ParseLine();

    //�ӻ����������ȡһ��
    char* GetLine();

    //����Ӧ����
    HTTP_CODE ParseRequest();

    //����Ӧ��������
    HTTP_CODE ParseReplyFirstLine(std::string content);

    //����Ӧ����ͷ
    HTTP_CODE ParseHeader(std::string content);

    //����Ӧ������
    HTTP_CODE ParseContent();

    //��ȡ��һ���ո����ڵ�λ�ã���û���򷵻�-1���򷵻ؿո��λ��
    int SearchSpace(std::string& content, int start);

    //��ȡ��һ���ַ����ڵ�λ�ã���û���򷵻�-1���򷵻��ַ���λ��
    int SearchCharacter(std::string& content, int start);

protected:
    std::unordered_map<std::string, std::string> m_requestHeader;   //�������ͷ��
    std::unordered_map<std::string, std::string> m_replyHeader;     //���Ӧ��ͷ����Ϣ
    std::string m_ip;                                               //��ŷ����ip
    int m_port;                                                     //��ŷ���˶˿�
    std::string m_url;                                              //�������url
    char* m_content = nullptr;                                      //�����Ҫ���͵�����
    int m_contentLength;                                            //�����Ҫ�������ݵĳ���
    char* m_replyContent = nullptr;                                 //���Ӧ������
    int m_replyContentLength;                                       //���Ӧ�����ݵĳ���


private:
    std::string m_replyVersion;                                     //���Ӧ������http�汾
    int m_stateCode;                                                //���Ӧ������״̬��
    std::string m_stateDescription;                                 //���״̬���Ӧ������

    int m_bufferSize;                                               //�������ռ�
    char* m_tmpBuffer = nullptr;                                    //��Ż�������С
    int m_checkIndex;                                               //��Ž���Ӧ������λ��
    int m_readLength;                                               //���Ӧ�������ȡ����
    int m_readIndex;                                                //����Ѿ��ӻ�������ȡ�����ݳ���
    int m_checkState;                                               //��ŵ�ǰ����״̬
};

#endif // HTTP_H