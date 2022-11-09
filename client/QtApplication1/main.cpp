#include <iostream>
#include "client.h"
#include <QtWidgets/QApplication>

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);
    Client w;
    w.show();
    return a.exec();
}



//˫����֤����
//#include <winsock2.h>
//#include <WS2tcpip.h>
//#pragma comment(lib,"ws2_32.lib")
//#include <string>
//#include <stdio.h>
//#include <string.h>
//#include <errno.h>
//#include <stdlib.h>
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//
//#include <WinSock2.h>
//
//#pragma comment(lib,"ws2_32.lib")
//
//#define MAXBUF 1024
//
//void ShowCerts(SSL* ssl)
//{
//    X509* cert;
//    char* line;
//
//    cert = SSL_get_peer_certificate(ssl);
//    // SSL_get_verify_result()���ص㣬SSL_CTX_set_verify()ֻ�������������ò�û��ִ����֤�����øú����Ż���֤����֤����֤
//    // �����֤��ͨ������ô�����׳��쳣��ֹ����
//    if (SSL_get_verify_result(ssl) == X509_V_OK) {
//        printf("֤����֤ͨ��\n");
//    }
//    if (cert != NULL) {
//        printf("����֤����Ϣ:\n");
//        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
//        printf("֤��: %s\n", line);
//        free(line);
//        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
//        printf("�䷢��: %s\n", line);
//        free(line);
//        X509_free(cert);
//    }
//    else
//        printf("��֤����Ϣ��\n");
//}
//
//int main(int argc, char** argv)
//{
//    WSADATA wsaData;
//    WSAStartup(MAKEWORD(2, 2), &wsaData);
//    int sockfd, len;
//    struct sockaddr_in dest;
//    char buffer[MAXBUF + 1];
//    SSL_CTX* ctx;
//    SSL* ssl;
//
//    /* SSL ���ʼ�����ο� ssl-server.c ���� */
//    SSL_library_init();
//    OpenSSL_add_all_algorithms();
//    SSL_load_error_strings();
//    ctx = SSL_CTX_new(SSLv23_client_method());
//    if (ctx == NULL) {
//        ERR_print_errors_fp(stdout);
//        exit(1);
//    }
//
//    // ˫����֤
//    // SSL_VERIFY_PEER---Ҫ���֤�������֤��û��֤��Ҳ�����
//    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT---Ҫ��ͻ�����Ҫ�ṩ֤�飬����֤���ֵ���ʹ��û��֤��Ҳ�����
//    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
//    // �������θ�֤��
//    if (SSL_CTX_load_verify_locations(ctx, "D:/lib/curl-openssl/ca/ca.crt", NULL) <= 0) {
//        ERR_print_errors_fp(stdout);
//        exit(1);
//    }
//
//    /* �����û�������֤�飬 ��֤���������͸��ͻ��ˡ� ֤��������й�Կ */
//    if (SSL_CTX_use_certificate_file(ctx, "D:/lib/curl-openssl/ca/client.crt", SSL_FILETYPE_PEM) <= 0) {
//        ERR_print_errors_fp(stdout);
//        exit(1);
//    }
//    /* �����û�˽Կ */
//    if (SSL_CTX_use_PrivateKey_file(ctx, "D:/lib/curl-openssl/ca/client_rsa_private.pem.unsecure", SSL_FILETYPE_PEM) <= 0) {
//        ERR_print_errors_fp(stdout);
//        exit(1);
//    }
//    /* ����û�˽Կ�Ƿ���ȷ */
//    if (!SSL_CTX_check_private_key(ctx)) {
//        ERR_print_errors_fp(stdout);
//        exit(1);
//    }
//
//    /* ����һ�� socket ���� tcp ͨ�� */
//    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
//        perror("Socket");
//        exit(errno);
//    }
//    printf("socket created\n");
//
//    /* ��ʼ���������ˣ��Է����ĵ�ַ�Ͷ˿���Ϣ */
//    memset(&dest, 0, sizeof(dest));
//    dest.sin_family = AF_INET;
//    dest.sin_port = htons(8888);
//    std::string ip = "192.168.1.130";
//    inet_pton(AF_INET, ip.c_str(), &dest.sin_addr.s_addr);
//
//    printf("address created\n");
//
//    /* ���ӷ����� */
//    if (connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) != 0) {
//        perror("Connect ");
//        exit(errno);
//    }
//    printf("server connected\n");
//
//    /* ���� ctx ����һ���µ� SSL */
//    ssl = SSL_new(ctx);
//    SSL_set_fd(ssl, sockfd);
//    /* ���� SSL ���� */
//    if (SSL_connect(ssl) == -1)
//        ERR_print_errors_fp(stderr);
//    else {
//        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
//        ShowCerts(ssl);
//    }
//
//    /* ���նԷ�����������Ϣ�������� MAXBUF ���ֽ� */
//    memset(buffer, 0, MAXBUF + 1);
//    /* ���շ�����������Ϣ */
//    len = SSL_read(ssl, buffer, MAXBUF);
//    if (len > 0)
//        printf("������Ϣ�ɹ�:'%s'����%d���ֽڵ�����\n",
//            buffer, len);
//    else {
//        printf
//        ("��Ϣ����ʧ�ܣ����������%d��������Ϣ��'%s'\n",
//            errno, strerror(errno));
//        goto finish;
//    }
//    memset(buffer, 0, MAXBUF + 1);
//    strcpy(buffer, "from client->server");
//    /* ����Ϣ�������� */
//    len = SSL_write(ssl, buffer, strlen(buffer));
//    if (len < 0)
//        printf
//        ("��Ϣ'%s'����ʧ�ܣ����������%d��������Ϣ��'%s'\n",
//            buffer, errno, strerror(errno));
//    else
//        printf("��Ϣ'%s'���ͳɹ�����������%d���ֽڣ�\n",
//            buffer, len);
//
//finish:
//    /* �ر����� */
//    SSL_shutdown(ssl);
//    SSL_free(ssl);
//    closesocket(sockfd);
//    SSL_CTX_free(ctx);
//    WSACleanup();
//    return 0;
//}