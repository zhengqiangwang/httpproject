#ifndef HTTPCONN_H
#define HTTPCONN_H


#include <netinet/in.h>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <unordered_map>
#include <string>
#include <vector>

class Database;

class Httpconn
{
public:
    Httpconn();
    ~Httpconn();

    void Process();
    void Init(int sockfd, const sockaddr_in &address);
    void Closeconn();
    char *DecodeData(char *EncryptData, int SetDataLen);
    char *EncodeData(char *source, int &len);
    bool Write();
    bool Read();

public:
    static int m_epollfd;
    static int m_user_count;
    static const int READ_BUF_SIZE = 2048;
    static const int WRITE_BUF_SIZE = 2048;
    static const int FILENAME_LEN = 200;
    static std::unordered_map<std::string, std::string> m_accounts;

    //HTTP请求方法，但我们只支持GET
    enum METHOD {GET = 0, POST, HEAD, PUT, DELETE, TRACE, OPTIONS, CONNECT};

    /*解析客户端请求时，主状态机的状态
     * CHECK_STATE_REQUESTLINE:当前正在分析请求行
     * CHECK_STATE_HEADER:当前正在分析头部字段
     * CHECK_STATE_CONTENT:当前正在解析请求体
     */
    enum CHECK_STATE{CHECK_STATE_REQUESTLINE = 0, CHECK_STATE_HEADER, CHECK_STATE_CONTENT};

    /*从状态机的三种可能状态，即行的读取状态，分别表示
     * 1.读取到一个完整的行 2.行出错 3.行数据尚且不完整
     */
    enum LINE_STATUS {LINE_OK = 0, LINE_BAD, LINE_OPEN};

    /*服务器处理HTTP请求的可能结果，报文解析的结果
     * NO_REQUEST          :  请求不完整，需要继续读取客户数据
     * GET_REQUEST         :  表示获得了一个完整的客户请求
     * BAD_REQUEST         :  表示客户请求语法错误
     * NO_RESOURCE         :  表示服务器没有资源
     * FORBIDDEN_REQUEST   :  表示客户对资源没有足够的访问权限
     * FILE_REQUEST        :  文件请求，获取文件成功
     * INTERNAL_ERROR      :  表示服务器内部错误
     * CLOSED_CONNECTION   :  表示客户端已经关闭连接了
     */
    enum HTTP_CODE {NO_REQUEST, GET_REQUEST, BAD_REQUEST, NO_RESOURCE, FORBIDDEN_REQUEST, FILE_REQUEST, INTERNAL_ERROR, CLOSED_CONNECTION};

private:
    HTTP_CODE ProcessResult();
    HTTP_CODE ParaseFirstLine(char *text);
    HTTP_CODE ParaseRequestHead(char *text);
    HTTP_CODE ParaseRequestContent(char *text);
    LINE_STATUS ParaseLine();
    void Init();
    char *GetLine();
    HTTP_CODE DoRequest(std::string path);
    void unmap();
    bool ProcessWrite(HTTP_CODE ret);
    bool AddResponse(const char* format, ...);
    bool AddStatusLine(int status, const char* title);
    bool AddHeaders(int content_len);
    bool AddContentLength(int content_len);
    bool AddLinger();
    bool AddBlankLine();
    bool AddContent(const char* content);
    bool AddContentType(std::string type);


    bool Register(std::string account);
    bool ReplyStatue(std::string status);
    bool ReplyImage(std::string pathe);
    bool ReplyArray(std::vector<std::string> pathes);

private:
    int m_socket;
    sockaddr_in m_address;
    char m_read_buf[READ_BUF_SIZE];
    int m_read_index;
    int m_check_index;
    int m_start_line;
    CHECK_STATE m_check_state;
    char *m_url;
    char *m_version;
    METHOD m_method;
    char *m_host;
    bool m_linger;
    int m_content_length;
    std::unordered_map<std::string, std::string> m_heads;

    char *m_content;

    char m_real_file[FILENAME_LEN];

    char m_write_buf[WRITE_BUF_SIZE];

    int m_write_idx;
    char *m_file_address;
    struct stat m_file_stat;
    struct iovec m_iv[2];
    int m_iv_count;
    char *m_index;
    bool m_map = false;
    unsigned char Key[AES_BLOCK_SIZE + 1];
    unsigned char ivec[AES_BLOCK_SIZE];
    AES_KEY AesKey;
    Database *database = nullptr;
};

#endif // HTTPCONN_H
