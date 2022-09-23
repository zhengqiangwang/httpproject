#include"MyDefine.h"
#include"CMyHttpServer.h"

int main()
{
#ifdef WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    std::cout << "Hello MyHttpServer!\n";

    CMyHttpServerMgr myHttpServerMgr(HTTP_SERVER_LISTEN_PORT);

    myHttpServerMgr.Start();
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    myHttpServerMgr.Stop();
    std::cout << "Stop MyHttpServer!\n";
    system("pause");

#ifdef WIN32
    WSACleanup();
#endif
}
