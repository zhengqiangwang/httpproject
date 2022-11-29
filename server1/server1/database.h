#ifndef DATABASE_H
#define DATABASE_H

#ifdef WIN32
#include <mysql.h>
#else
#include <mysql/mysql.h>
#endif

#include <string>
#include <vector>

class Cryptogram;

class Database
{
public:
    static Database* GetInstance()
    {
        if (!Instance)
        {
            Instance = new Database;
        }
        return  Instance;
    }
    bool InitDb(std::string host, std::string user, std::string pwd, std::string dbname);
    bool ExecSQL(std::string sql);
    bool Longin(std::string account, std::string password);
    std::string Register(std::string name, std::string password);
    bool CreateTable(std::string account);
    std::string AddImage(std::string account, std::string pathe, std::string length);
    bool QueryImage(std::string account, std::vector<std::string>& result);
    std::string QueryRoute(std::string account, std::string pathe);
    std::string QueryLength(std::string account, std::string pathe);

private:
    Database();
    ~Database();

private:
    MYSQL* m_mysql = nullptr;          //linke handle
    MYSQL_RES* m_result = nullptr;        //point qurey result
    MYSQL_ROW row;
    static Database* Instance;
    Cryptogram* m_cryptogram = nullptr;
};

#endif // DATABASE_H
