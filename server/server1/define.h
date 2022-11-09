#ifndef DEFINE_H
#define DEFINE_H

#define HTTP_SERVER_LISTEN_IP		"0.0.0.0"							//http服务监听地址
#define HTTP_SERVER_LISTEN_PORT		8888								//http服务监听端口

#ifdef  WIN32
#define WORKINGPATH "D:/vscode/code/server1/server1"
#define CLIENT_CA_FILE "D:/lib/curl-openssl/ca/ca.crt"
#define CLIENT_CERT_FILE "D:/lib/curl-openssl/ca/server.crt"
#define CLIENT_KEY_FILE  "D:/lib/curl-openssl/ca/server_rsa_private.pem.unsecure"
#define LOG_PATH "."
#define INTERVAL 60
#define ACCESSNUMBER 60
#define STRICTTIME 60
#else
#define WORKINGPATH "."
#define CLIENT_CA_FILE "/home/wang/linuxca/ca.crt"
#define CLIENT_CERT_FILE "/home/wang/linuxca/linux_server.crt"
#define CLIENT_KEY_FILE  "/home/wang/linuxca/linux_server_rsa_private.pem.unsecure"
#define LOG_PATH "."
#define INTERVAL 60
#define ACCESSNUMBER 60
#define STRICTTIME 60
#endif //  WIN32


#endif // DEFINE_H
