#ifndef DEFINE_H
#define DEFINE_H
#include <string>

//const std::string serverIp = "192.168.88.128";							//vmware linux http��������ַ
//const std::string serverIp = "120.78.82.230";							//�����Ʒ�����
const std::string serverIp = "192.168.1.130";							//windows http��������ַ
const int port = 8888;													//http�������˿�

#ifdef WIN32
#define CLIENT_CA_FILE "D:/lib/curl-openssl/ca/ca.crt"
#define CLIENT_CERT_FILE "D:/lib/curl-openssl/ca/client.crt"
#define CLIENT_KEY_FILE  "D:/lib/curl-openssl/ca/client_rsa_private.pem.unsecure"
#else
#define CLIENT_CA_FILE "/home/wang/linuxca/ca.crt"
#define CLIENT_CERT_FILE "/home/wang/linuxca/client.crt"
#define CLIENT_KEY_FILE  "/home/wang/linuxca/client_rsa_private.pem.unsecure"
#endif //WIN32

#endif // DEFINE_H
