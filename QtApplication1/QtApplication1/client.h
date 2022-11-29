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

    //�û�ѡ����Ҫ�ϴ���ͼƬ�ļ�������ͼƬ��ʾ���ϴ��б���
    void AcquireFile();

    //��ȡ�û�������Ϣ
    void AcquireMessage();

    //ɾ����ǰѡ��ͼƬ�����ϴ��б��е������Դ��ϴ��б���ȡ����ǰ���ͼƬ�ϴ�
    void DeleteImage();

    //�ϴ��û��ϴ��б��е�ͼƬ������Ѿ��ϴ�����ʾ�Ѿ��ϴ��������ϴ���ǰͼƬ
    void UpImage();

    //����˫���Ŵ���ʾͼƬ
    void DoubleClicked();

    //��ͼƬ�Ŵ���ʾʱ����������򷵻���ҳ��
    void ReturnMain();

    //����ͼƬ��ʾҳ��
    void HideImagePage();

    //������ҳ��
    void HideMainPage();

    //��ʾͼƬ��ʾҳ��
    void ShowImagePage();

    // ��ʾ��ҳ��
    void ShowMainPage();

    //�����������һ��ͼƬ�ļ�
    bool SendOneImage(std::string path);

    //�û���¼ϵͳ
    bool Login();

    //�û�ע���˺�
    bool Register();

    //��ȡ�û��ϴ����ļ�����ʾ
    bool GetImageRoutes();

    //���ݴ����·���б���ʾͼƬ
    bool ShowImages(std::vector<std::string> pathes);

    //�û��˳���¼
    void closeEvent(QCloseEvent* event);

private:
    Ui::clientClass* m_ui;                                      //ui������
    std::vector<std::string> m_uplist;                          //ͼƬ�ϴ�·���б�
    std::string m_password;                                     //�����ȡ���û�����
    std::string m_account;                                      //�����ȡ���û��ʺ�
    std::string m_name;                                         //�����ȡ���û�����
    std::unordered_map<std::string, std::string> m_images;      //�������ϴ����ļ��ļ����Լ��洢·����
    UserBroker* m_userbroker = nullptr;                         //�û�������
};