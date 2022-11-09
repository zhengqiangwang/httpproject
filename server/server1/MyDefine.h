#ifndef MYDEFINE_H
#define MYDEFINE_H

#define HTTP_SERVER_LISTEN_IP		"0.0.0.0"							//http服务监听地址
#define HTTP_SERVER_LISTEN_PORT		8888								//http服务监听端口

#define HTTP_CLIENT_REGISTER        "/client?Action=Register"           //系统注册URI
#define HTTP_CLIENT_LOGIN			"/client?Action=Login"				//系统登录URI
#define HTTP_CLIENT_LOGOUT			"/client?Action=Logout"				//系统登出URI
#define HTTP_CLIENT_HEARBEAT		"/client?Action=Heartbeat"			//心跳URI

#define WORKINGPATH "D:/vscode/code/server1/server1"
/*
*  系统各种业务请求URL宏定义，格式与登录、登出、心跳类似
*/


#endif // MYDEFINE_H
