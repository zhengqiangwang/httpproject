#ifndef HTTP_H
#define HTTP_H

#include <string>
#include <unordered_map>
#include <event2/http.h>

class Database;

class Http
{
public:
    Http();
    int Init(int port, std::string ip);
    void test();
    static void dump_login_cb(struct evhttp_request *req, void *arg);

public:
    static std::unordered_map<std::string, std::string> m_accounts;

private:
    void Init();
    std::unordered_map<std::string, std::string> m_heads;
    Database *database = nullptr;
};

#endif // HTTP_H
