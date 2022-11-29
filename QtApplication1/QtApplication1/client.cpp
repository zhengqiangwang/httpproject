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

    //�����ź����
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
    m_ui->upimage->setViewMode(QListWidget::IconMode);//��ʾģʽ
    m_ui->upimage->setIconSize(QSize(100, 100));//����ͼƬ��С
    m_ui->upimage->setSpacing(10);//���
    m_ui->upimage->setResizeMode(QListView::Adjust);//��Ӧ���ֵ���
    m_ui->upimage->setMovement(QListView::Static);//�����ƶ�

    m_ui->downimage->setViewMode(QListWidget::IconMode);//��ʾģʽ
    m_ui->downimage->setIconSize(QSize(100, 100));//����ͼƬ��С
    m_ui->downimage->setSpacing(10);//���
    m_ui->downimage->setResizeMode(QListView::Adjust);//��Ӧ���ֵ���
    m_ui->downimage->setMovement(QListView::Static);//�����ƶ�
}

//�����������ͷ���Դ
Client::~Client()
{
#ifdef WIN32
    WSACleanup();
#endif
    delete m_ui;
}

//�û�ѡ����Ҫ�ϴ���ͼƬ�ļ�������ͼƬ��ʾ���ϴ��б���
void Client::AcquireFile()
{
    //QFileDialog �ṩ�˷ǳ���ľ�̬������������һ���Ի��򣬶Ի���������������ѡ���ļ������ļ���ʱ�����ѡ����
    //�ļ�������Ҳ���Բ�ʹ�þ�̬��������QFileDialog ��������һ���Ի���ʵ�л�һ������

    QFileDialog fileDialog(this);

    //���ô��ڵı���
    fileDialog.setWindowTitle(QString::fromLocal8Bit("��ѡ��ͼƬ�ļ�"));
    fileDialog.setNameFilter("*.png *.jpeg *.jpg *.gif *.bmp"); //����һ��������,�ܹ���ȡ�ļ��ĺ�׺��

    //�����־��������ѡ������ͣ�����Ĭ���ǵ����ļ���QFileDialog::ExistingFiles ����ļ�,����������ѡ���ļ���QFileDialog::Directory��QFileDialog::ExistingFile �����ļ���ע�����ExistingFile�����ʺ������һ��s ��ʾѡ�����ļ���Ҫ������ˡ�
    fileDialog.setFileMode(QFileDialog::ExistingFiles);


    QString str;
    //�����Ի���
    if (fileDialog.exec() == QDialog::Accepted)
    {
        //strPathList  ����ֵ��һ��list������ǵ����ļ�ѡ��Ļ���ֻҪȡ����һ���������ˡ�
        QStringList strPathList = fileDialog.selectedFiles();
        for (int i = 0; i < strPathList.size(); ++i) {
            qDebug() << strPathList.at(i);
            str = strPathList.at(i);
            m_uplist.emplace_back(str.toStdString());
        }

    }

    //��ʾ�û�Ҫ�ϴ���ͼƬ
    for (int i = 0; i < m_uplist.size(); i++)
    {
        QListWidgetItem* imageItem = new QListWidgetItem;
        imageItem->setIcon(QIcon(m_uplist[i].data()));
        imageItem->setSizeHint(QSize(120, 100));
        m_ui->upimage->addItem(imageItem);
    }
}

//��ȡ�û�������Ϣ
void Client::AcquireMessage()
{
    m_account = m_ui->usrname->text().toStdString();
    m_name = m_account;
    m_password = m_ui->password->text().toStdString();
    m_ui->usrname->setText("");
    m_ui->password->setText("");
}

//ɾ����ǰѡ��ͼƬ�����ϴ��б��е������Դ��ϴ��б���ȡ����ǰ���ͼƬ�ϴ�
void Client::DeleteImage()
{
    QListWidgetItem* item = m_ui->upimage->currentItem();//��ѡ�л򱳵����itemɾ��
    int row = m_ui->upimage->currentRow();
    m_uplist.erase(m_uplist.begin() + row);
    m_ui->upimage->removeItemWidget(item);
    delete item;

}

//�ϴ��û��ϴ��б��е�ͼƬ������Ѿ��ϴ�����ʾ�Ѿ��ϴ��������ϴ���ǰͼƬ
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

//����˫���Ŵ���ʾͼƬ
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

//��ͼƬ�Ŵ���ʾʱ����������򷵻���ҳ��
void Client::ReturnMain()
{
    ShowMainPage();
    HideImagePage();
}

//����ͼƬ��ʾҳ��
void Client::HideImagePage()
{
    m_ui->image->hide();
    m_ui->returned->hide();
}

//������ҳ��
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

//��ʾͼƬ��ʾҳ��
void Client::ShowImagePage()
{
    m_ui->image->show();
    m_ui->returned->show();
}

//��ʾ��ҳ��
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

//����һ��ͼƬ�ļ�
bool Client::SendOneImage(std::string path)
{
    std::vector<std::string> paths;
    paths.emplace_back(path);
    m_userbroker->SendFiles(paths);

    return true;
}

//�û���¼ϵͳ
bool Client::Login()
{
    AcquireMessage();
    std::string result = m_userbroker->Longin(m_account, m_password);

    result = "Login " + result;
    QMessageBox::information(this, "Login Message", QString::fromStdString(result));
    GetImageRoutes();

    return true;
}

//�û�ע���˺�
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

//��ȡ�û��ϴ����ļ�����ʾ
bool Client::GetImageRoutes()
{
    std::vector<std::string> paths = m_userbroker->FlushFiles();
    std::cout << paths.size() << std::endl;
    ShowImages(paths);

    return true;
}

//���ݴ����·���б���ʾͼƬ
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
    std::cout << "�رճɹ�" <<result<< std::endl;
}
