#ifndef MYHTTPCMDDEF_H
#define MYHTTPCMDDEF_H

#include"MyHeader.h"

//HTTP请求消息映射结构体
struct HTTPReqInfo
{
    //HTTP消息处理关键字
    const char* cmdKey;

    //HTTP消息处理函数地址
    int(*called_fun)(evhttp_request* pstReq, const string& data, void* userData);
};

struct HTTPReqInfoMap
{
    //请求消息索引
    int index;

    //HTTP请求命令
    struct HTTPReqInfo* cmd;
};

//存储HTTP命令请求的map表
typedef map<string, HTTPReqInfoMap> HTTP_REQ_INFO_MAP;

#endif // MYHTTPCMDDEF_H
