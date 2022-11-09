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

    //初始化服务器的ip和端口
    bool Init(std::string ip, int port);

    //用户注册帐号
    std::string Register(std::string name, std::string password);

    //用户登录系统
    std::string Longin(std::string account, std::string password);

    //用户退出系统
    bool Exit(std::string account);

    //将文件列表中的文件发送给服务器，返回发送是否成功的列表
    std::vector<bool> SendFiles(std::vector<std::string> paths);

    //刷新显示文件
    std::vector<std::string> FlushFiles();

    //获取文件当前用户所有上传图片的路径
    std::vector<std::string> AcquirePaths();

    //path is request path, route is store path
    bool GetFile(std::string path, std::string route);

private:
    std::string m_account = "";         //保存用户帐号
    std::string m_password = "";        //保存用户密码
    std::string m_token = "";           //保存用于验证合法性的token

    Cryptogram* m_cry = nullptr;        //加密处理句柄      
    Http* m_http = nullptr;             //HTTP发送和接收句柄 
};

#endif // USERBROKER_H#pragma once
