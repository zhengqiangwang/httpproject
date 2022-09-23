#include "network.h"
#include "database.h"

#include "http.h"

#include"MyDefine.h"
#include"CMyHttpServer.h"

int main(int argc, char *argv[])
{


//使用socket自己进行解析
//    Network network;
//    network.Init("", 8888);
//    network.Listen();
//    while(true)
//    {
//        network.Dispatch();
//    }
//    network.Close();




//使用libevent中http单线程，未写完
//    Http http;
//    http.Init(8888, "");





//使用libevent中http多线程
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

    return 0;
}

