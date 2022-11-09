#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include "userbroker.h"
#include "cryptogram.h"
#include "plainhttp.h"
#include "curlhttp.h"
#include "define.h"

using json = nlohmann::json;

UserBroker::UserBroker() : m_cry{ new Cryptogram }, m_http{ new PlainHttp }
{

}

UserBroker::~UserBroker()
{

}

bool UserBroker::Init(std::string ip, int port)
{
    if (!m_http->SetIpaddress(ip))
    {
        return false;
    }

    if (!m_http->SetPort(port))
    {
        return false;
    }

    return true;
}

std::string UserBroker::Register(std::string name, std::string password)
{
    if (name == "" || password == "")
    {
        return "";
    }

    password = m_cry->Md5Encode(password);
    password = m_cry->Base64Encode(password.c_str(), password.size());

    m_http->ClearRequest();

    if (!m_http->SetUrl("/client?Action=Register"))
    {
        return "";
    }

    json user;
    user["name"] = name;
    user["password"] = password;

    std::string content = user.dump();

    if (content == "")
    {
        return "";
    }

    if (!m_http->SetRequestContent(content.c_str(), content.size()))
    {
        return "";
    }

    if (!m_http->SendPost())
    {
        return "";
    }

    m_http->ClearReply();

    if (!m_http->AcquireReply())
    {
        return "";
    }

    std::string reply = "";
    reply = m_http->GetReplyContent();
    if (reply == "")
    {
        return "";
    }

    json respond = json::parse(reply);
    if (respond.find("account") == respond.end())
    {
        return "";
    }

    return respond["account"];
}

std::string UserBroker::Longin(std::string account, std::string password)
{
    if (account == "" || password == "")
    {
        return "error";
    }

    password = m_cry->Md5Encode(password);
    password = m_cry->Base64Encode(password.c_str(), password.size());

    m_http->ClearRequest();

    if (!m_http->SetUrl("/client?Action=Login"))
    {
        return "error";
    }

    std::string host = serverIp + ":" + std::to_string(port);

    if (!m_http->SetRequestHeader("Host", host))
    {
        return "error";
    }

    if (!m_http->SetRequestHeader("Connection", "keep-alive"))
    {
        return "error";
    }

    if (!m_http->SetRequestHeader("Content-Type", "application/json"))
    {
        return "error";
    }

    json user;
    user["account"] = account;
    user["password"] = password;

    std::string content = user.dump();

    if (content == "")
    {
        return "error";
    }

    if (!m_http->SetRequestContent(content.c_str(), content.size()))
    {
        return "error";
    }

    if (!m_http->SendPost())
    {
        return "error";
    }

    m_http->ClearReply();

    if (!m_http->AcquireReply())
    {
        return "error";
    }

    std::string reply = "";
    reply = m_http->GetReplyContent();
    std::cout << "reply:" << reply << std::endl;
    if (reply == "")
    {
        return "error";
    }

    json respond = json::parse(reply);
    if (respond.find("status") == respond.end())
    {
        return "error";
    }

    if (respond["status"] == "success")
    {
        m_password = password;
        m_account = account;
    }
    if (respond["status"] != "fail")
    {
        m_token = m_http->GetReplyHeader("Set-Cookie");
        std::cout << m_token << std::endl;
    }
    std::cout << respond["status"] << std::endl;
    return respond["status"];
}

bool UserBroker::Exit(std::string account)
{
    bool result = false;

    m_http->ClearRequest();
    
    if (!m_http->SetUrl("/client?Action=Exit"))
    {
        return result;
    }

    if (!m_http->SetRequestHeader("Set-Cookie", m_token))
    {
        return result;
    }
  
    if (!m_http->SendPost())
    {
        return result;
    }
    
    m_http->ClearReply();

    if (!m_http->AcquireReply())
    {
        return result;
    }

    int length = m_http->GetReplyContentLen();
    if (!length)
    {
        return result;
    }

    std::string reply = m_http->GetReplyContent();

    if (reply == "")
    {
        return result;
    }

    json respond = json::parse(reply);
    if (respond.find("status") == respond.end())
    {
        return "error";
    }

    if (respond["status"] == "success")
    {
        return true;
    }
    if (respond["status"] != "fail")
    {
        return result;
    }

    return result;
}

std::vector<bool> UserBroker::SendFiles(std::vector<std::string> paths)
{
    int pathlen = paths.size();
    std::vector<bool> result(pathlen, false);

    if (!pathlen)
    {
        return result;
    }

    

    for (int i = 0; i < pathlen; i++)
    {
        m_http->ClearRequest();
        std::string url = paths[i];
        if (url == "")
        {
            continue;
        }

        if (url[0] != '/')
        {
            url = "/" + url;
        }

        if (!m_http->SetUrl(url))
        {
            return result;
        }

        struct stat filestat;
        if (stat(paths[i].c_str(), &filestat) < 0) {
            exit(-1);
        }

        FILE* file = fopen(paths[i].c_str(), "rb");
        if (!file)
        {
            continue;
        }
        char* content = new char[filestat.st_size];
        memset(content, 0, filestat.st_size);
        fread(content, 1, filestat.st_size, file);
        fclose(file);
        //³õÊ¼»¯easy hand

        if (!m_http->SetRequestHeader("Set-Cookie", m_token))
        {
            continue;
        }

        if (!m_http->SetRequestContent(content, filestat.st_size))
        {
            continue;
        }

        if (!m_http->SendPost())
        {
            continue;
        }

        delete[] content;

        m_http->ClearReply();

        if (!m_http->AcquireReply())
        {
            continue;
        }

        result[i] = true;
    }

    return result;
}

std::vector<std::string> UserBroker::FlushFiles()
{
    std::vector<std::string> paths = AcquirePaths();

    int pathlen = paths.size();

    std::vector<std::string> result;
    for (int i = 0; i < pathlen; i++)
    {
        std::cout << paths[i] << " " << i << std::endl;
        std::string path = std::to_string(i) + ".jpg";
        if (GetFile(paths[i], path))
        {
            result.emplace_back(path);
        }
        else
        {
            result.emplace_back("");
        }
    }

    return result;
}

std::vector<std::string> UserBroker::AcquirePaths()
{
    std::vector<std::string> result;
    if (m_account == "")
    {
        return result;
    }

    m_http->ClearRequest();

    if (!m_http->SetUrl("/files?"))
    {
        return result;
    }

    if (!m_http->SetRequestHeader("Set-Cookie", m_token))
    {
        return result;
    }

    if (!m_http->SendGet())
    {
        return result;
    }

    m_http->ClearReply();

    if (!m_http->AcquireReply())
    {
        return result;
    }

    int length = m_http->GetReplyContentLen();
    if (!length)
    {
        return result;
    }

    std::string content = m_http->GetReplyContent();

    if (content == "")
    {
        return result;
    }

    std::cout << content << std::endl;
    
    json paths = json::parse(content);
    if (paths.find("paths") == paths.end())
    {
        return result;
    }
   
    std::vector<std::string> path = paths["paths"];

    return path;
}

bool UserBroker::GetFile(std::string path, std::string route)
{
    bool result = false;
    if (path == "" || route == "")
    {
        return result;
    }

    m_http->ClearRequest();

    if (!m_http->SetUrl(path))
    {
        return result;
    }

    if (!m_http->SetRequestHeader("Set-Cookie", m_token))
    {
        return result;
    }

    if (!m_http->SendGet())
    {
        return result;
    }

    m_http->ClearReply();

    if (!m_http->AcquireReply())
    {
        return result;
    }

    int length = m_http->GetReplyContentLen();
    if (!length)
    {
        return result;
    }

    char* content = m_http->GetReplyContent();
    if (!content)
    {
        return result;
    }

    FILE* fp;
    if ((fp = fopen(route.c_str(), "wb+")) == NULL)
    {
        return result;
    }

    int relen = fwrite(content, 1, length, fp);
    if (relen != length)
    {
        return result;
    }

    fclose(fp);

    return true;
}