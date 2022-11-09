#include "database.h"
#include <iostream>7
#include <string>
#include <thread>
#include "cryptogram.h"

Database* Database::Instance = nullptr;

Database::Database():m_cryptogram{new Cryptogram}
{
    m_mysql = mysql_init(nullptr);   //初始化数据库连接变量
    if (m_mysql == nullptr)
    {
        std::cout << "Error:" << mysql_error(m_mysql);
        exit(1);
    }
    InitDb("localhost", "root", "~Wang43456364", "test");
    m_cryptogram->Init();
}

Database::~Database()
{
    if (m_mysql != nullptr)  //关闭数据连接
    {
        mysql_close(m_mysql);
    }
}

bool Database::InitDb(std::string host, std::string user, std::string pwd, std::string dbname)
{
    std::cout << "initdb" << std::endl;
    m_mysql = mysql_real_connect(m_mysql, host.c_str(), user.c_str(), pwd.c_str(), dbname.c_str(), 0, nullptr, 0);
    if (m_mysql == nullptr)
    {
        std::cout << "Error: " << mysql_error(m_mysql);
        exit(1);
    }

    std::string sql = "CREATE TABLE IF NOT EXISTS `usr`  ( \
            `id` varchar(30),\
            `name` varchar(30),\
            `password` varchar(64),\
            `salt` varchar(17),\
            PRIMARY KEY(`id`)\
            ) ";
    int re = mysql_query(m_mysql, sql.c_str());//从字符串换成const char*
    if (re != 0)
    {
        std::cout << "mysql_query failed!" << mysql_error(m_mysql) << std::endl;
    }
    return true;

}

bool Database::ExecSQL(std::string sql)
{
    //mysql_query()执行成功返回0,执行失败返回非0值。
    if (mysql_query(m_mysql, sql.c_str()))
    {
        std::cout << "Query Error: " << mysql_error(m_mysql);
        return false;
    }
    else // 查询成功
    {
        m_result = mysql_store_result(m_mysql);  //获取结果集
        if (m_result)  // 返回了结果集
        {
            int  num_fields = mysql_num_fields(m_result);   //获取结果集中总共的字段数，即列数
            int  num_rows = mysql_num_rows(m_result);       //获取结果集中总共的行数
            for (int i = 0; i < num_rows; i++) //输出每一行
            {
                //获取下一行数据
                row = mysql_fetch_row(m_result);
                if (row == nullptr) break;

                for (int j = 0; j < num_fields; j++)  //输出每一字段
                {
                    std::cout << row[j] << "\t\t";
                }
                std::cout << std::endl;
            }

        }
        else  // result==NULL
        {
            if (mysql_field_count(m_mysql) == 0)   //代表执行的是update,insert,delete类的非查询语句
            {
                // (it was not a SELECT)
                int num_rows = mysql_affected_rows(m_mysql);  //返回update,insert,delete影响的行数
            }
            else // error
            {
                std::cout << "Get result error: " << mysql_error(m_mysql);
                return false;
            }
        }
        m_result = nullptr;
    }

    return true;
}

bool Database::Longin(std::string account, std::string password)
{
    std::cout << "login" << std::this_thread::get_id()<< std::endl;
    std::string sql = "SELECT salt, password FROM usr where id = '" + account + "';";
    int re = mysql_query(m_mysql, sql.c_str());//从字符串换成const char*
    if (re != 0)
    {
        std::cout << "mysql_query failed!" << mysql_error(m_mysql) << std::endl;
        return false;
    }
    m_result = mysql_store_result(m_mysql);
    if (m_result)
    {
        row = mysql_fetch_row(m_result);
        if (row == nullptr)
        {
            mysql_free_result(m_result);
            return false;
        }
        std::string salt = row[0];
        std::string str = row[1];
        password += salt;
        password = m_cryptogram->Md5Encode(password);
        password = m_cryptogram->Base64Encode(password.c_str(), password.size());
        mysql_free_result(m_result);
        return str == password;
    }
    mysql_free_result(m_result);
    return  false;
}

std::string Database::Register(std::string name, std::string password)
{
    std::cout << "database register----------" << std::endl;
    std::string salt = m_cryptogram->CreateSalt();
    password += salt;
    password = m_cryptogram->Md5Encode(password);
    password = m_cryptogram->Base64Encode(password.c_str(), password.size());
    std::cout << "database register----------" << std::endl;
    int account = 0;
    int mid = 0;
    std::string sql = "SELECT id FROM usr;";
    int re = mysql_query(m_mysql, sql.c_str());//从字符串换成const char*
    if (re != 0)
    {
        std::cout << "mysql_query failed!" << mysql_error(m_mysql) << std::endl;
    }
    m_result = mysql_store_result(m_mysql);  //获取结果集
    if (m_result)  // 返回了结果集
    {
        int  num_rows = mysql_num_rows(m_result);       //获取结果集中总共的行数
        for (int i = 0; i < num_rows; i++) 
        {
            //获取下一行数据
            row = mysql_fetch_row(m_result);
            if (row == nullptr) break;
            mid = atoi(row[0]);
            if (mid > account)
            {
                account = mid;
            }

            std::cout << mid << std::endl;
        }
        mysql_free_result(m_result);
    }
    m_result = nullptr;
    account++;

    sql = "INSERT INTO usr ( id, name, password, salt) VALUES  ( '" + std::to_string(account) + "', '" + name + "', '" + password + "', '" + salt + "');";
    std::cout << sql << std::endl;
    re = mysql_query(m_mysql, sql.c_str());//从字符串换成const char*
    if (re != 0)
    {
        std::cout << "mysql_query insert failed!" << mysql_error(m_mysql) << std::endl;
        return "";
    }
    return std::to_string(account);

}

bool Database::CreateTable(std::string account)
{
    std::string sql = "CREATE TABLE IF NOT EXISTS image" + account + "  ( pathe varchar(1000), route varchar(10), length varchar(10) );";
    std::cout << sql << std::endl;
    int re = mysql_query(m_mysql, sql.c_str());//从字符串换成const char*
    if (re != 0)
    {
        std::cout << "mysql_query failed!" << mysql_error(m_mysql) << std::endl;
        return false;
    }
    return true;

}

std::string Database::AddImage(std::string account, std::string pathe, std::string length)
{
    int index = 0;
    int mid = 0;
    std::string sql = "SELECT route FROM image" + account + ";";
    int re = mysql_query(m_mysql, sql.c_str());//从字符串换成const char*
    if (re != 0)
    {
        std::cout << "mysql_query failed!" << mysql_error(m_mysql) << std::endl;
    }
    m_result = mysql_store_result(m_mysql);  //获取结果集
    if (m_result)  // 返回了结果集
    {
        int  num_rows = mysql_num_rows(m_result);       //获取结果集中总共的行数
        for (int i = 0; i < num_rows; i++) //输出每一行
        {
            //获取下一行数据
            row = mysql_fetch_row(m_result);
            if (row == nullptr) break;
            mid = atoi(row[0]);
            if (mid > index)
            {
                index = mid;
            }

            std::cout << mid << std::endl;
        }
        mysql_free_result(m_result);
    }
    m_result = nullptr;
    index++;

    sql = "INSERT INTO image" + account + " ( pathe , route, length) VALUES  ( '" + pathe + "', '" + std::to_string(index) + "', '" + length + "');";
    std::cout << sql << std::endl;
    re = mysql_query(m_mysql, sql.c_str());//从字符串换成const char*
    if (re != 0)
    {
        std::cout << "mysql_query insert failed!" << mysql_error(m_mysql) << std::endl;
        return "";
    }
    return std::to_string(index);
}

bool Database::QueryImage(std::string account, std::vector<std::string>& result)
{
    std::string sql = "SELECT pathe FROM image" + account + ";";
    int re = mysql_query(m_mysql, sql.c_str());//从字符串换成const char*
    if (re != 0)
    {
        std::cout << "mysql_query failed!" << mysql_error(m_mysql) << std::endl;
    }
    m_result = mysql_store_result(m_mysql);  //获取结果集
    if (m_result)  // 返回了结果集
    {
        int  num_rows = mysql_num_rows(m_result);       //获取结果集中总共的行数
        for (int i = 0; i < num_rows; i++) //输出每一行
        {
            //获取下一行数据
            row = mysql_fetch_row(m_result);
            if (row == nullptr) break;
            result.emplace_back(row[0]);
        }
        mysql_free_result(m_result);
        return true;
    }
    return false;
}

std::string Database::QueryRoute(std::string account, std::string pathe)
{
    std::string sql = "SELECT route FROM image" + account + " where pathe = '" + pathe + "';";
    std::cout << sql << std::endl;
    int re = mysql_query(m_mysql, sql.c_str());//从字符串换成const char*
    if (re != 0)
    {
        std::cout << "mysql_query failed!" << mysql_error(m_mysql) << std::endl;
    }

    std::string result = "";

    m_result = mysql_store_result(m_mysql);  //获取结果集
    if (m_result)  // 返回了结果集
    {
        int  num_rows = mysql_num_rows(m_result);       //获取结果集中总共的行数
        for (int i = 0; i < num_rows; i++) //输出每一行
        {
            //获取下一行数据
            row = mysql_fetch_row(m_result);
            if (row == nullptr) break;

            result = row[0];
        }
        mysql_free_result(m_result);
    }
    return result;
}

std::string Database::QueryLength(std::string account, std::string pathe)
{
    std::string sql = "SELECT length FROM image" + account + " where pathe = '" + pathe + "';";
    std::cout << sql << std::endl;
    int re = mysql_query(m_mysql, sql.c_str());//从字符串换成const char*
    if (re != 0)
    {
        std::cout << "mysql_query failed!" << mysql_error(m_mysql) << std::endl;
    }
    std::string result = "";
    m_result = mysql_store_result(m_mysql);  //获取结果集
    if (m_result)  // 返回了结果集
    {
        int  num_rows = mysql_num_rows(m_result);       //获取结果集中总共的行数
        for (int i = 0; i < num_rows; i++) //输出每一行
        {
            //获取下一行数据
            row = mysql_fetch_row(m_result);
            if (row == nullptr) break;
       
            result = row[0];
            break;
        }
        
        mysql_free_result(m_result);
    }
    return result;
}