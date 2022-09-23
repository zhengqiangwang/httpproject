#include "httpconn.h"
#include <cstdio>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <stdarg.h>

#include "database.h"

#include <iostream>

#include <json.hpp>
using json = nlohmann::json;


int Httpconn::m_epollfd = -1;
int Httpconn::m_user_count = 0;
std::unordered_map<std::string, std::string> Httpconn::m_accounts;
const char *ok_200_title = "OK";
const char *error_400_title = "Bad Request";
const char *error_400_form = "Your request has bad syntax or is inherently impossible";
const char *error_403_title = "Forbidden";
const char *error_403_form = "You do not have permission to get file from this server";
const char *error_404_title = "Not Found";
const char *error_404_form = "The request file was not found on this server";
const char *error_500_title = "Internal Error";
const char *error_500_form = "There was an unusual problem serving the";

const char *doc_root = "/home/wang/test5/resources";

void SetNonblocking(int fd){
    int flag = fcntl(fd, F_GETFL);
    flag |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flag);
}

void Addfd(int epollfd, int fd, bool one_shot){
    epoll_event event;
    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLHUP;

    if(one_shot){
        event.events |= EPOLLONESHOT;
    }
    epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
    SetNonblocking(fd);
}

void Removefd(int epollfd, int fd){
    epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);
}

void Modefd(int epollfd, int fd, int ev){
    epoll_event event;
    event.data.fd = fd;
    event.events = ev | EPOLLONESHOT | EPOLLHUP;

    epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event);
}

Httpconn::Httpconn()
{

}

Httpconn::~Httpconn()
{

}

void Httpconn::Process()
{
    printf("process\n");
    Httpconn::HTTP_CODE read_ret = ProcessResult();
    if(read_ret == NO_REQUEST){
        Modefd(m_epollfd, m_socket, EPOLLIN);
        return;
    }
    for(auto &m : m_heads)
    {
        std::cout<<m.first<<"  "<<m.second<<std::endl;
    }
    if(m_method == GET){
        bool write_ret = false;
        if(m_heads["Content-Type"] == "application/json")
        {
            std::cout<<m_heads["Content-Length"]<<"  "<<m_content<<std::endl;
            json j3=json::parse(m_content);
            std::cout<<j3["account"]<<"  "<<j3["password"]<<std::endl;
            //            std::string account = database->Register("wang", j3["password"]);
            //            if(account != "")
            //            {
            //                std::cout<<account<<std::endl;
            //            }
            if(database->Longin(j3["account"], j3["password"]))
            {
                std::cout<<"Login success"<<std::endl;
                std::string password = j3["password"];
                m_accounts[password] = j3["account"];
                write_ret = ReplyStatue("success");
            }
            else
            {
                std::cout<<"Login fail"<<std::endl;
                write_ret = ReplyStatue("fail");
            }
        }
        else
        {
            std::string cookie = m_heads["Set-Cookie"];
            std::string account = "";
            if(m_accounts.find(cookie) == m_accounts.end())
            {
                std::cout<<"user is not login"<<std::endl;
            }
            else
            {
                account = m_accounts[cookie];
                std::cout<<"user is login"<<std::endl;
            }
            std::string type = m_heads["Content-Type"];
            type = type.substr(0, 5);
            if(type == "image")
            {
                std::string path = database->QueryRoute(account, m_url);
                if(path != "")
                {
                    path = "/" + account + "/" + path;
                    write_ret = ReplyImage(path);
                }
                else
                {
                    std::cout<<"require image route failed"<<std::endl;
                }

            }
            else
            {

                std::vector<std::string> path;
                database->QueryImage(account, path);
                write_ret = ReplyArray(path);
            }
        }
        //bool write_ret = ProcessWrite(read_ret);
        if(!write_ret){
            Closeconn();
        }
        Modefd(m_epollfd, m_socket, EPOLLOUT);
    }
    else if(m_method == POST)
    {
        std::string cookie = m_heads["Set-Cookie"];
        std::string account = "";
        if(m_accounts.find(cookie) == m_accounts.end())
        {
            std::cout<<"user is not login"<<std::endl;
        }
        else
        {
            account = m_accounts[cookie];
            std::string subp = database->AddImage(account, m_url, std::to_string(m_content_length));

            std::cout<<"user is login"<<std::endl;
            account = "/" + account;
            std::cout<<"post"<<std::endl;
            strcpy(m_real_file, doc_root);
            int len = strlen(doc_root);
            strncpy(m_real_file + len, account.data(), account.size());
            len = strlen(m_real_file);

            //        int fd = open(m_real_file, O_WRONLY | O_CREAT);
            //        write(fd, m_content, m_content_length);
            //        close(fd);

            if(subp == "")
            {
                std::cout<<"add image fail"<<std::endl;
            }
            else
            {
                subp = "/" + subp;
                strncpy(m_real_file + len, subp.data(), subp.size());
                FILE* fp;
                std::cout<<m_real_file<<std::endl;
                if ((fp = fopen(m_real_file, "wb+")) == NULL)
                {
                    printf("File.\n");

                }
                int length = 0;
                char *encode = EncodeData(m_content, length);
                FILE *fp1 = nullptr;
                if((fp1 = fopen("wang", "wb+")) == nullptr)
                {
                    printf("open wang file fail");
                }
                else
                {
                    int l = fwrite(encode, 1, length, fp1);
                    fclose(fp1);
                    std::cout<<"input fp1 "<<l<<" size."<<std::endl;
                }
                if(stat("wang", &m_file_stat) < 0){
                    std::cout<<"acquire file message fail"<<std::endl;
                }
                else
                {
                    std::cout<<"file size "<<m_file_stat.st_size<<"   "<<length<<std::endl;
                    if((fp1 = fopen("wang", "rb")) == nullptr)
                    {
                        printf("open wang file fail");
                    }
                    else
                    {
                        int l = fread(encode, 1, m_file_stat.st_size, fp1);
                        std::cout<<"read fp1 "<<l<<"size."<<std::endl;
                    }
                }

                m_content = DecodeData(encode, length);
                int l = fwrite(m_content, 1, m_content_length, fp);
                fclose(fp);
                std::cout<<"write success "<<l<<std::endl;
                Init();
                Modefd(m_epollfd, m_socket, EPOLLIN);
            }

        }

    }
}

void Httpconn::Init(int sockfd, const sockaddr_in &address)
{
    m_socket = sockfd;
    m_address = address;

    int reuse = 1;
    setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    Addfd(m_epollfd, m_socket, true);
    m_user_count++;
    Init();
}

void Httpconn::Closeconn()
{
    if(m_socket != -1){
        m_user_count--;
        Removefd(m_epollfd, m_socket);
        m_socket = -1;
    }
}

bool Httpconn::Write()
{
    int temp = 0;
    int bytes_have_send = 0;
    int bytes_to_send = m_write_idx;

    if(bytes_to_send == 0){
        Modefd(m_epollfd, m_socket, EPOLLIN);
        Init();
        return true;
    }

    while(1){
        temp = writev(m_socket, m_iv, m_iv_count);
        std::cout<<"send: "<<temp<<std::endl;
        if(temp <= -1){
            if(errno == EAGAIN){
                Modefd(m_epollfd, m_socket, EPOLLOUT);
                return true;
            }
            if(m_iv_count == 2)
            {
                if(m_map)
                {
                    unmap();
                    m_map = false;
                }
                else
                {
                    delete (char *)m_iv[1].iov_base;
                }
            }
            return false;
        }
        bytes_to_send -= temp;
        bytes_have_send += temp;
        if(bytes_to_send <= bytes_have_send){
            if(m_iv_count == 2)
            {
                if(m_map)
                {
                    unmap();
                    m_map = false;
                }
                else
                {
                    delete (char *)m_iv[1].iov_base;
                }
            }
            if(m_linger){
                Init();
                Modefd(m_epollfd, m_socket, EPOLLIN);
                return true;
            }else{
                Modefd(m_epollfd, m_socket, EPOLLIN);
                return false;
            }
        }
    }
    return true;
}

bool Httpconn::Read()
{
    std::cout<<"read"<<std::endl;
    if(m_read_index >= READ_BUF_SIZE){
        return false;
    }

    int read_byte = 0;
    while(READ_BUF_SIZE - m_read_index){
        read_byte = recv(m_socket,m_read_buf + m_read_index, READ_BUF_SIZE - m_read_index, 0);
        std::cout<<"read byte "<<read_byte<<std::endl;
        if(read_byte == -1){
            if(errno == EAGAIN && errno == EWOULDBLOCK){
                break;
            }
            return false;
        }else if(read_byte == 0){
            Closeconn();
            return false;
        }
        m_read_index += read_byte;
    }

    //    printf("%s\n", m_read_buf);

    return true;
}

Httpconn::HTTP_CODE Httpconn::ProcessResult()
{
    LINE_STATUS line_statu = LINE_OK;
    HTTP_CODE ret = NO_REQUEST;

    char *text = 0;

    while((m_check_state == CHECK_STATE_CONTENT && line_statu == LINE_OK)||((line_statu = ParaseLine()) == LINE_OK)){
        std::cout<<"check state "<<m_check_state<<std::endl;
        text = GetLine();
        m_start_line = m_check_index;

        switch(m_check_state){
        case CHECK_STATE_REQUESTLINE:{
            ret = ParaseFirstLine(text);
            if(ret == BAD_REQUEST){
                return BAD_REQUEST;
            }
            break;
        }
        case CHECK_STATE_HEADER:{
            ret = ParaseRequestHead(text);
            if(ret == BAD_REQUEST){
                return BAD_REQUEST;
            }else if(ret == GET_REQUEST){
                if(m_method == GET)
                {
                    return FILE_REQUEST;
                }
            }
            break;
        }
        case CHECK_STATE_CONTENT:{
            ret = ParaseRequestContent(text);
            if(ret == GET_REQUEST){
                if(m_method == GET)
                {
                    return FILE_REQUEST;
                }
                else if(m_method == POST)
                {
                    return ret;
                }
            }

            line_statu = LINE_OPEN;
            break;

        }
        default:{
            return INTERNAL_ERROR;
        }
        }
    }
    return NO_REQUEST;
}

Httpconn::HTTP_CODE Httpconn::ParaseFirstLine(char *text)
{
    std::cout<<"parase first line: "<<text<<std::endl;
    m_url = strpbrk(text, " \t");
    *m_url++ = '\0';
    char *method = text;
    if(strcasecmp(method, "GET") == 0){
        m_method = GET;
    }else if(strcasecmp(method, "POST") == 0){
        m_method = POST;
    }
    else{
        return BAD_REQUEST;
    }

    m_version = strpbrk(m_url, " \t");
    if(!m_version){
        return BAD_REQUEST;
    }
    *m_version++ = '\0';
    if(strcasecmp(m_version , "HTTP/1.1") != 0){
        return BAD_REQUEST;
    }

    if(strncasecmp(m_url, "http://", 7) == 0){
        m_url += 7;
        m_url = strchr(m_url, '/');
    }

    if(!m_url || m_url[0] != '/'){
        return BAD_REQUEST;
    }
    std::cout<<"url: "<<m_url<<std::endl;
    m_check_state = CHECK_STATE_HEADER;

    return NO_REQUEST;
}

Httpconn::HTTP_CODE Httpconn::ParaseRequestHead(char *text)
{
    if(text[0] == '\0'){
        if(m_content_length != 0){
            m_check_state = CHECK_STATE_CONTENT;
            return NO_REQUEST;
        }
        return GET_REQUEST;
    }
    //    std::cout<<text<<std::endl;
    int i = 0;
    char key[100] = {0};
    char value[1000] = {0};
    int keyl = 0;
    int valuel = 0;
    while(text[i] != '\r')
    {
        if(text[i] == ' ')
        {
            i++;
            continue;
        }
        break;
    }
    keyl = i;
    while(text[i] != '\r')
    {
        if(text[i] == ' ' || text[i] == ':')
        {
            break;
        }
        i++;
    }
    memcpy(key, text + keyl, i - keyl);
    i++;
    while(text[i] != '\r')
    {
        if(text[i] == ' ')
        {
            i++;
            continue;
        }
        break;
    }
    valuel = i;
    while(text[i] != '\r')
    {
        i++;
    }
    memcpy(value, text + valuel, i - valuel);
    m_heads[key] = value;
    //    std::cout<<key<<"  "<<value<<std::endl;
    if(strncasecmp(text, "Connection:", 11) == 0){
        text += 11;
        text += strspn(text, " \t");
        if(strcasecmp(text, "keep-alive") == 0){
            m_linger = true;
        }
    }else if(strncasecmp(text, "Content-Length:", 15) == 0){
        text += 15;
        text += strspn(text, " \t");
        m_content_length = atol(text);
    }else if(strncasecmp(text, "Host:", 5) == 0){
        text += 5;
        text += strspn(text, " \t");
        m_host = text;
    }else{
        printf("oop! unknow header %s\n", text);
    }

    return NO_REQUEST;
}

Httpconn::HTTP_CODE Httpconn::ParaseRequestContent(char *text)
{

    if(m_read_index >= (m_content_length + m_check_index)){
        text[m_content_length] = '\0';
        m_content = new char[m_content_length + 1];
        memset(m_content, 0, m_content_length + 1);
        memcpy(m_content, text, m_content_length);
        return GET_REQUEST;
    }
    else
    {
        m_content = new char[m_content_length + 1];
        if(!m_content)
        {
            std::cout<<"new faile\n";
        }
        memset(m_content, 0, m_content_length + 1);
        memcpy(m_content, text, m_read_index - m_check_index);
        std::cout<<"m_check_index: "<<m_check_index<<std::endl;
        int read_byte = 0;
        int read_index = 0;
        read_index = m_read_index - m_check_index;
        printf("read_index:%d",read_index);
        while(read_index != m_content_length){
            read_byte = recv(m_socket,m_content + read_index, m_content_length - read_index, 0);
            if(read_byte == -1){
                if(errno == EAGAIN || errno == EWOULDBLOCK){
                    printf("sdaflkasdjflkjlkasdjf");
                    break;
                }
                exit(-1);
            }else if(read_byte == 0){
                Closeconn();
                exit(-1);
            }
            std::cout<<"content len: "<<m_content_length<<",read index:"<<read_index<<std::endl;
            read_index += read_byte;
        }

        //        for(size_t i=0;i<m_content_length;i++){
        //            printf("%d ",(int)m_content[i]);
        //            if(i%10==0){
        //                printf("\n");
        //            }
        //        }
        //std::cout<<"content len: "<<m_content_length<<",read index:"<<read_index<<std::endl;
        return GET_REQUEST;
    }
    return NO_REQUEST;
}

Httpconn::LINE_STATUS Httpconn::ParaseLine()
{
    char temp;

    for(; m_check_index < m_read_index; ++m_check_index){
        temp = m_read_buf[m_check_index];
        if(temp == '\r'){
            if((m_check_index + 1) == m_read_index){
                return LINE_OPEN;
            } else if(m_read_buf[m_check_index + 1] == '\n'){
                m_read_buf[m_check_index++] = '\0';
                m_read_buf[m_check_index++] = '\0';
                return LINE_OK;
            }
            return LINE_BAD;
        }else if(temp == '\n'){
            if((m_check_index > 1)&& (m_read_buf[m_check_index -1] == '\r')){
                m_read_buf[m_check_index - 1] = '\0';
                m_read_buf[m_check_index++] = '\0';
                return LINE_OK;
            }
            return LINE_BAD;
        }

    }

    return LINE_OPEN;
}

void Httpconn::Init()
{
    m_check_index = 0;
    m_check_state = CHECK_STATE_REQUESTLINE;
    m_start_line = 0;
    m_url = 0;
    m_method = GET;
    m_version = 0;
    m_linger = false;
    m_content_length = 0;
    m_write_idx = 0;
    m_host = 0;
    m_read_index = 0;
    bzero(m_read_buf, READ_BUF_SIZE);
    bzero(m_write_buf, WRITE_BUF_SIZE);
    bzero(m_real_file, FILENAME_LEN);
    m_index = "0.jpg";
    memset(Key, 0x00, sizeof(Key));
    memcpy(Key, "0123456789abcdef", AES_BLOCK_SIZE);
    database = Database::GetInstance();
}

char *Httpconn::GetLine()
{
    return m_read_buf + m_start_line;
}

Httpconn::HTTP_CODE Httpconn::DoRequest(std::string path)
{
    strcpy(m_real_file, doc_root);
    int len = strlen(doc_root);
    strncpy(m_real_file + len, path.data(), FILENAME_LEN - len -1);

    if(stat(m_real_file, &m_file_stat) < 0){
        return NO_REQUEST;
    }

    if(!(m_file_stat.st_mode & S_IROTH)){
        return FORBIDDEN_REQUEST;
    }

    if(S_ISDIR(m_file_stat.st_mode)){
        return BAD_REQUEST;
    }

    int fd = open(m_real_file, O_RDONLY);
    m_file_address = (char *)mmap(0, m_file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    m_map = true;
    close(fd);
    return FILE_REQUEST;
}

void Httpconn::unmap(){
    if(m_file_address){
        munmap(m_file_address, m_file_stat.st_size);
        m_file_address = 0;
    }
}

bool Httpconn::ProcessWrite(HTTP_CODE ret)
{
    switch(ret){
    case INTERNAL_ERROR:
        AddStatusLine(500, error_500_title);
        AddHeaders(strlen(error_500_form));
        if(!AddContent(error_500_form)){
            return false;
        }
        break;
    case BAD_REQUEST:
        AddStatusLine(400, error_400_title);
        AddHeaders(strlen(error_400_form));
        if(!AddContent(error_400_form)){
            return false;
        }
        break;
    case NO_RESOURCE:
        AddStatusLine(404, error_400_title);
        AddHeaders(strlen(error_404_form));
        if(!AddContent(error_404_form)){
            return false;
        }
        break;
    case FORBIDDEN_REQUEST:
        AddStatusLine(403, error_403_title);
        AddHeaders(strlen(error_403_form));
        if(!AddContent(error_403_form)){
            return false;
        }
        break;
    case FILE_REQUEST:
        AddStatusLine(200, ok_200_title);
        AddHeaders(m_file_stat.st_size);
        m_iv[0].iov_base = m_write_buf;
        m_iv[0].iov_len = m_write_idx;
        //            m_iv[1].iov_base = m_file_address;
        //            m_iv[1].iov_len = m_file_stat.st_size;
        m_iv_count = 1;
        return true;
    default:
        return false;
    }
}

bool Httpconn::AddResponse(const char* format, ...)
{
    if(m_write_idx >= WRITE_BUF_SIZE){
        return false;
    }
    va_list arg_list;
    va_start(arg_list, format);
    int len = vsnprintf(m_write_buf + m_write_idx, WRITE_BUF_SIZE - 1 - m_write_idx, format, arg_list);
    if(len >= (WRITE_BUF_SIZE - 1 - m_write_idx)){
        return false;
    }
    m_write_idx += len;
    va_end(arg_list);
    return true;

}

bool Httpconn::AddStatusLine(int status, const char *title)
{
    return AddResponse("%s %d %s\r\n","HTTP/1.1",status,title);
}

bool Httpconn::AddHeaders(int content_len)
{
    AddContentLength(content_len);
    AddContentType("text/xml");
    AddLinger();
    AddBlankLine();
}

bool Httpconn::AddContentLength(int content_len)
{
    return AddResponse("Content-Length:%d\r\n", content_len);
}

bool Httpconn::AddLinger()
{
    return AddResponse("Connection: %s\r\n", (m_linger == true) ? "keep-alive":"close");
}

bool Httpconn::AddBlankLine()
{
    return AddResponse("%s","\r\n");
}

bool Httpconn::AddContent(const char *content)
{

}

bool Httpconn::AddContentType(std::string type)
{
    return AddResponse("Content-Type:%s\r\n", type.c_str());
}

char *Httpconn::DecodeData(char *EncryptData, int SetDataLen)
{
    int i = 0;
    char *DecryptData = nullptr;

    DecryptData = (char *)calloc(SetDataLen + 1, sizeof (char));
    if(DecryptData == nullptr)
    {
        std::cout<<"Unable to allocate memory for DecryptData"<<std::endl;
        exit(-1);
    }

    memset(&AesKey, 0x00, sizeof (AES_KEY));
    if(AES_set_decrypt_key(Key, 128, &AesKey) < 0)
    {
        std::cout<<"Unable to set encryption key in AES .."<<std::endl;
        exit(-1);
    }

    for(i = 0; i < AES_BLOCK_SIZE; i++)
    {
        ivec[i] = 0;
    }

    AES_cbc_encrypt((unsigned char *) EncryptData, (unsigned char *)DecryptData, SetDataLen, &AesKey, ivec, AES_DECRYPT);
    std::cout<<"DecryptData:"<<DecryptData<<std::endl;
    return DecryptData;
}

char *Httpconn::EncodeData(char *source, int &len)
{
    char *InputData = nullptr;
    char *EncryptData = nullptr;

    int DataLen = 0;
    int SetDataLen = 0;
    int i = 0;

    DataLen = m_content_length;

    SetDataLen = 0;
    if((DataLen % AES_BLOCK_SIZE) == 0)
    {
        SetDataLen = DataLen;
    }
    else
    {
        SetDataLen = ((DataLen / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    }
    std::cout<<"SetDataLen:"<<SetDataLen<<"..."<<std::endl;
    len = SetDataLen;

    InputData = (char *)calloc(SetDataLen + 1, sizeof (char));
    if(InputData == nullptr)
    {
        std::cout<<"Unable to allocate memory for InputData"<<std::endl;
        exit(-1);
    }
    memcpy(InputData, source, DataLen);

    EncryptData = (char *)calloc(SetDataLen + 1, sizeof(char));
    if(EncryptData == nullptr)
    {
        std::cout<<"Unable to allocate memory for EncryptData"<<std::endl;
        exit(-1);
    }

    memset(&AesKey, 0x00, sizeof (AES_KEY));
    if(AES_set_encrypt_key(Key, 128, &AesKey) < 0)
    {
        std::cout<<"Unable to set encryption key in AES .."<<std::endl;
        exit(-1);
    }

    for(i = 0; i < AES_BLOCK_SIZE; i++)
    {
        ivec[i] = 0;
    }

    AES_cbc_encrypt((unsigned char *) InputData, (unsigned char *) EncryptData, SetDataLen, &AesKey, ivec, AES_ENCRYPT);

    std::cout<<"EncryptData:"<<EncryptData<<std::endl;
    return EncryptData;
}

bool Httpconn::Register(std::string account)
{
    if(database->CreateTable(account))
    {
        int len = strlen(doc_root);
        char *dir = new char[len];
        memcpy(dir, doc_root, len);
        std::string str = "/" + account;
        memcpy(dir + len, str.data(), str.size());
        std::cout<<dir<<std::endl;
        int ret = mkdir(dir, 0777);
        if(ret == 0)
        {
            std::cout<<"dir create success"<<std::endl;
            return true;
        }
    }
    return false;
}

bool Httpconn::ReplyStatue(std::string status)
{
    json state;
    state["status"] = status;
    std::string s = state.dump();

    char *content = new char[s.size() + 1];
    memset(content,0,s.size() + 1);
    memcpy(content, s.data(), s.size());
    std::cout<<s<<" "<<s.size()<<"  "<<strlen(content)<<" "<<sizeof (content)<<std::endl;
    AddStatusLine(200, ok_200_title);
    AddContentLength(strlen(content));
    AddContentType("application/json");
    AddLinger();
    AddBlankLine();
    m_iv[0].iov_base = m_write_buf;
    m_iv[0].iov_len = m_write_idx;
    m_iv[1].iov_base = content;
    m_iv[1].iov_len = strlen(content);
    m_iv_count = 2;
    return true;
}

bool Httpconn::ReplyImage(std::string pathe)
{
    if(!DoRequest(pathe))
    {
        return false;
    }
    AddStatusLine(200, ok_200_title);
    AddContentLength(m_file_stat.st_size);
    AddContentType("image/jpeg");
    AddLinger();
    AddBlankLine();
    m_iv[0].iov_base = m_write_buf;
    m_iv[0].iov_len = m_write_idx;
    m_iv[1].iov_base = m_file_address;
    m_iv[1].iov_len = m_file_stat.st_size;
    m_iv_count = 2;
    return true;
}

bool Httpconn::ReplyArray(std::vector<std::string> pathes)
{
    json path;
    path["pathes"] = pathes;
    std::string s = path.dump();
    char *content = new char[s.size() + 1];
    memset(content,0,s.size() + 1);
    memcpy(content, s.data(), s.size());
    std::cout<<s<<" "<<s.size()<<"  "<<strlen(content)<<" "<<m_write_idx<<std::endl;
    AddStatusLine(200, ok_200_title);


    std::string str = "application/json";
    std::cout<<"index"<<std::endl;


    AddContentType(str);
    std::cout<<"construct success"<<std::endl;
    AddLinger();
    AddContentLength(strlen(content));
    AddBlankLine();
    m_iv[0].iov_base = m_write_buf;
    m_iv[0].iov_len = m_write_idx;
    m_iv[1].iov_base = content;
    m_iv[1].iov_len = strlen(content);
    m_iv_count = 2;

    return true;
}



