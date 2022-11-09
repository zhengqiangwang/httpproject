#ifndef MYHTTPCMDDEF_H
#define MYHTTPCMDDEF_H

#include"MyHeader.h"

//HTTP������Ϣӳ��ṹ��
struct HTTPReqInfo
{
    //HTTP��Ϣ����ؼ���
    const char* cmdKey;

    //HTTP��Ϣ��������ַ
    int(*called_fun)(evhttp_request* pstReq, const string& data, void* userData);
};

struct HTTPReqInfoMap
{
    //������Ϣ����
    int index;

    //HTTP��������
    struct HTTPReqInfo* cmd;
};

//�洢HTTP���������map��
typedef map<string, HTTPReqInfoMap> HTTP_REQ_INFO_MAP;

#endif // MYHTTPCMDDEF_H
