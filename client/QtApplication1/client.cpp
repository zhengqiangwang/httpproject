#include "client.h"
#include <iostream>
#include <QFileDialog>
#include <QDebug>
#include <QString>
#include <QListWidget>
#include <QLabel>
#include <QListWidgetItem>
#include <QPainter>
#include <QMessageBox>
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include "userbroker.h"
#include "define.h"

#ifdef WIN32
#pragma comment(lib,"ws2_32.lib")
#endif

using json = nlohmann::json;

Client::Client(QWidget* parent)
    : QMainWindow(parent)
    , m_ui(new Ui::clientClass())
{
#ifdef WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif 


    m_userbroker = new UserBroker;

    if (m_userbroker->Init(serverIp, port))  
    {
        std::cout << "init success" << std::endl;
    }

    m_ui->setupUi(this);

    //连接信号与槽
    QObject::connect(m_ui->select, &QPushButton::clicked, this, &Client::AcquireFile);
    QObject::connect(m_ui->login, &QPushButton::clicked, this, &Client::Login);
    QObject::connect(m_ui->registered, &QPushButton::clicked, this, &Client::Register);
    QObject::connect(m_ui->up, &QPushButton::clicked, this, &Client::UpImage);
    QObject::connect(m_ui->flush, &QPushButton::clicked, this, &Client::GetImageRoutes);
    QObject::connect(m_ui->returned, &QPushButton::clicked, this, &Client::ReturnMain);
    QObject::connect(m_ui->upimage, &QListWidget::itemClicked, this, &Client::DeleteImage);
    QObject::connect(m_ui->downimage, &QListWidget::itemDoubleClicked, this, &Client::DoubleClicked);

    HideImagePage();
    m_ui->password->setPlaceholderText("password");
    m_ui->usrname->setPlaceholderText("account");
    m_ui->upimage->setViewMode(QListWidget::IconMode);//显示模式
    m_ui->upimage->setIconSize(QSize(100, 100));//设置图片大小
    m_ui->upimage->setSpacing(10);//间距
    m_ui->upimage->setResizeMode(QListView::Adjust);//适应布局调整
    m_ui->upimage->setMovement(QListView::Static);//不能移动

    m_ui->downimage->setViewMode(QListWidget::IconMode);//显示模式
    m_ui->downimage->setIconSize(QSize(100, 100));//设置图片大小
    m_ui->downimage->setSpacing(10);//间距
    m_ui->downimage->setResizeMode(QListView::Adjust);//适应布局调整
    m_ui->downimage->setMovement(QListView::Static);//不能移动
}

//析构函数，释放资源
Client::~Client()
{
#ifdef WIN32
    WSACleanup();
#endif
    delete m_ui;
}

//用户选择需要上传的图片文件，并将图片显示在上传列表中
void Client::AcquireFile()
{
    //QFileDialog 提供了非常多的静态函数，用来打开一个对话框，对话框可以用来保存和选择文件，打开文件的时候可以选择多个
    //文件。我们也可以不使用静态函数，用QFileDialog 对象来打开一个对话框。实列化一个对象

    QFileDialog fileDialog(this);

    //设置窗口的标题
    fileDialog.setWindowTitle(QString::fromLocal8Bit("请选择图片文件"));
    fileDialog.setNameFilter("*.png *.jpeg *.jpg *.gif *.bmp"); //设置一个过滤器,能够获取文件的后缀名

    //这个标志用来设置选择的类型，比如默认是单个文件。QFileDialog::ExistingFiles 多个文件,还可以用来选择文件夹QFileDialog::Directory。QFileDialog::ExistingFile 单个文件。注意这个ExistingFile，单词后面多了一个s 表示选择多个文件。要看清楚了。
    fileDialog.setFileMode(QFileDialog::ExistingFiles);


    QString str;
    //弹出对话框
    if (fileDialog.exec() == QDialog::Accepted)
    {
        //strPathList  返回值是一个list，如果是单个文件选择的话，只要取出第一个来就行了。
        QStringList strPathList = fileDialog.selectedFiles();
        for (int i = 0; i < strPathList.size(); ++i) {
            qDebug() << strPathList.at(i);
            str = strPathList.at(i);
            m_uplist.emplace_back(str.toStdString());
        }

    }

    //显示用户要上传的图片
    for (int i = 0; i < m_uplist.size(); i++)
    {
        QListWidgetItem* imageItem = new QListWidgetItem;
        imageItem->setIcon(QIcon(m_uplist[i].data()));
        imageItem->setSizeHint(QSize(120, 100));
        m_ui->upimage->addItem(imageItem);
    }
}

//获取用户个人信息
void Client::AcquireMessage()
{
    m_account = m_ui->usrname->text().toStdString();
    m_name = m_account;
    m_password = m_ui->password->text().toStdString();
    m_ui->usrname->setText("");
    m_ui->password->setText("");
}

//删除当前选中图片，在上传列表中单击可以从上传列表中取消当前点击图片上传
void Client::DeleteImage()
{
    QListWidgetItem* item = m_ui->upimage->currentItem();//被选中或背点击的item删除
    int row = m_ui->upimage->currentRow();
    m_uplist.erase(m_uplist.begin() + row);
    m_ui->upimage->removeItemWidget(item);
    delete item;

}

//上传用户上传列表中的图片，如果已经上传则提示已经上传而放弃上传当前图片
void Client::UpImage()
{
    int len = m_uplist.size();
    for (int i = 0; i < len; i++)
    {
        if (m_images.find(m_uplist[i]) == m_images.end())
        {
            bool sendresult = SendOneImage(m_uplist[i]);
            if (sendresult)
            {
                int size = m_images.size();
                m_images.emplace(m_uplist[i], std::to_string(size));
            }
            else
            {
                QMessageBox::information(this, "image", "first Pictures send failed");
            }
            

            QListWidgetItem* item = m_ui->upimage->takeItem(0);
            delete item;
        }
        else
        {
            QMessageBox::information(this, "image", "first Pictures have been uploaded");
            QListWidgetItem* item = m_ui->upimage->takeItem(0);
            delete item;
        }

    }
    m_uplist.clear();
}

//处理双击放大显示图片
void Client::DoubleClicked()
{
    int row = m_ui->downimage->currentRow();
    std::string path = "";
    path += std::to_string(row) + ".jpg";
    QPixmap pixmap(path.c_str());
    pixmap = pixmap.scaled(m_ui->image->width(), m_ui->image->height(), Qt::KeepAspectRatio, Qt::SmoothTransformation);
    m_ui->image->setPixmap(pixmap);
    ShowImagePage();
    HideMainPage();
}

//在图片放大显示时，点击返回则返回主页面
void Client::ReturnMain()
{
    ShowMainPage();
    HideImagePage();
}

//隐藏图片显示页面
void Client::HideImagePage()
{
    m_ui->image->hide();
    m_ui->returned->hide();
}

//隐藏主页面
void Client::HideMainPage()
{
    m_ui->downimage->hide();
    m_ui->upimage->hide();
    m_ui->flush->hide();
    m_ui->login->hide();
    m_ui->password->hide();
    m_ui->registered->hide();
    m_ui->select->hide();
    m_ui->up->hide();
    m_ui->usrname->hide();
}

//显示图片显示页面
void Client::ShowImagePage()
{
    m_ui->image->show();
    m_ui->returned->show();
}

//显示主页面
void Client::ShowMainPage()
{
    m_ui->downimage->show();
    m_ui->upimage->show();
    m_ui->flush->show();
    m_ui->login->show();
    m_ui->password->show();
    m_ui->registered->show();
    m_ui->select->show();
    m_ui->up->show();
    m_ui->usrname->show();
}

//发送一个图片文件
bool Client::SendOneImage(std::string path)
{
    std::vector<std::string> paths;
    paths.emplace_back(path);
    m_userbroker->SendFiles(paths);

    return true;
}

//用户登录系统
bool Client::Login()
{
    AcquireMessage();
    std::string result = m_userbroker->Longin(m_account, m_password);

    result = "Login " + result;
    QMessageBox::information(this, "Login Message", QString::fromStdString(result));
    GetImageRoutes();

    return true;
}

//用户注册账号
bool Client::Register()
{
    AcquireMessage();
    std::string result = m_userbroker->Register(m_name, m_password);
    if (result != "")
    {
        result = "account: " + result;
        QMessageBox::information(this, "Register Message", QString::fromStdString(result));
        return true;
    }
    else
    {
        QMessageBox::information(this, "Register Message", "Register fail");
        return false;
    }
    return false;
}

//获取用户上传的文件并显示
bool Client::GetImageRoutes()
{
    std::vector<std::string> paths = m_userbroker->FlushFiles();
    std::cout << paths.size() << std::endl;
    ShowImages(paths);

    return true;
}

//根据传入的路径列表显示图片
bool Client::ShowImages(std::vector<std::string> pathes)
{
    int len = m_ui->downimage->count();
    std::cout << "show image len:" << len << std::endl;
    for (int i = 0; i < len; i++)
    {
        QListWidgetItem* item = m_ui->downimage->takeItem(0);
        delete item;
    }
    for (int i = 0; i < pathes.size(); i++)
    {
        QListWidgetItem* imageItem = new QListWidgetItem;
        imageItem->setIcon(QIcon(pathes[i].data()));
        imageItem->setSizeHint(QSize(120, 100));
        m_ui->downimage->addItem(imageItem);
    }
    return true;
}

void Client::closeEvent(QCloseEvent* event)
{
    std::cout << "close window" << std::endl;
    bool result = m_userbroker->Exit(m_account);
    std::cout << "关闭成功" <<result<< std::endl;
}
