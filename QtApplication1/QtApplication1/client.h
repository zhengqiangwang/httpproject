#pragma once

#include <QtWidgets/QMainWindow>
#include <QCloseEvent> 
#include "ui_client.h"
#include <string>
#include <vector>
#include <unordered_map>

class UserBroker;
class Httpconn;

QT_BEGIN_NAMESPACE
namespace Ui { class clienttestClass; };
QT_END_NAMESPACE

class Client : public QMainWindow
{
    Q_OBJECT

public:
    Client(QWidget* parent = nullptr);

    ~Client();

    //用户选择需要上传的图片文件，并将图片显示在上传列表中
    void AcquireFile();

    //获取用户个人信息
    void AcquireMessage();

    //删除当前选中图片，在上传列表中单击可以从上传列表中取消当前点击图片上传
    void DeleteImage();

    //上传用户上传列表中的图片，如果已经上传则提示已经上传而放弃上传当前图片
    void UpImage();

    //处理双击放大显示图片
    void DoubleClicked();

    //在图片放大显示时，点击返回则返回主页面
    void ReturnMain();

    //隐藏图片显示页面
    void HideImagePage();

    //隐藏主页面
    void HideMainPage();

    //显示图片显示页面
    void ShowImagePage();

    // 显示主页面
    void ShowMainPage();

    //向服务器发送一个图片文件
    bool SendOneImage(std::string path);

    //用户登录系统
    bool Login();

    //用户注册账号
    bool Register();

    //获取用户上传的文件并显示
    bool GetImageRoutes();

    //根据传入的路径列表显示图片
    bool ShowImages(std::vector<std::string> pathes);

    //用户退出登录
    void closeEvent(QCloseEvent* event);

private:
    Ui::clientClass* m_ui;                                      //ui界面句柄
    std::vector<std::string> m_uplist;                          //图片上传路径列表
    std::string m_password;                                     //保存获取的用户密码
    std::string m_account;                                      //保存获取的用户帐号
    std::string m_name;                                         //保存获取的用户名字
    std::unordered_map<std::string, std::string> m_images;      //保存已上传的文件文件名以及存储路径名
    UserBroker* m_userbroker = nullptr;                         //用户代管者
};