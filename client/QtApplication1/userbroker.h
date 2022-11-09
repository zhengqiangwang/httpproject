#ifndef USERBROKER_H
#define USERBROKER_H

#include <string>
#include <vector>

class Cryptogram;
class Http;

class UserBroker
{
public:
    UserBroker();
    ~UserBroker();

    //��ʼ����������ip�Ͷ˿�
    bool Init(std::string ip, int port);

    //�û�ע���ʺ�
    std::string Register(std::string name, std::string password);

    //�û���¼ϵͳ
    std::string Longin(std::string account, std::string password);

    //�û��˳�ϵͳ
    bool Exit(std::string account);

    //���ļ��б��е��ļ����͸������������ط����Ƿ�ɹ����б�
    std::vector<bool> SendFiles(std::vector<std::string> paths);

    //ˢ����ʾ�ļ�
    std::vector<std::string> FlushFiles();

    //��ȡ�ļ���ǰ�û������ϴ�ͼƬ��·��
    std::vector<std::string> AcquirePaths();

    //path is request path, route is store path
    bool GetFile(std::string path, std::string route);

private:
    std::string m_account = "";         //�����û��ʺ�
    std::string m_password = "";        //�����û�����
    std::string m_token = "";           //����������֤�Ϸ��Ե�token

    Cryptogram* m_cry = nullptr;        //���ܴ�����      
    Http* m_http = nullptr;             //HTTP���ͺͽ��վ�� 
};

#endif // USERBROKER_H#pragma once
