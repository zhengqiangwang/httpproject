/********************************************************************************
** Form generated from reading UI file 'client.ui'
**
** Created by: Qt User Interface Compiler version 5.15.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CLIENT_H
#define UI_CLIENT_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_clientClass
{
public:
    QWidget *centralWidget;
    QPushButton *login;
    QPushButton *select;
    QPushButton *registered;
    QLineEdit *usrname;
    QLineEdit *password;
    QPushButton *up;
    QPushButton *flush;
    QListWidget *downimage;
    QListWidget *upimage;
    QLabel *image;
    QPushButton *returned;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *clientClass)
    {
        if (clientClass->objectName().isEmpty())
            clientClass->setObjectName(QString::fromUtf8("clientClass"));
        clientClass->resize(600, 400);
        centralWidget = new QWidget(clientClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        login = new QPushButton(centralWidget);
        login->setObjectName(QString::fromUtf8("login"));
        login->setGeometry(QRect(500, 50, 75, 23));
        select = new QPushButton(centralWidget);
        select->setObjectName(QString::fromUtf8("select"));
        select->setGeometry(QRect(40, 310, 75, 23));
        registered = new QPushButton(centralWidget);
        registered->setObjectName(QString::fromUtf8("registered"));
        registered->setGeometry(QRect(500, 10, 75, 23));
        usrname = new QLineEdit(centralWidget);
        usrname->setObjectName(QString::fromUtf8("usrname"));
        usrname->setGeometry(QRect(40, 10, 171, 31));
        password = new QLineEdit(centralWidget);
        password->setObjectName(QString::fromUtf8("password"));
        password->setGeometry(QRect(270, 10, 171, 31));
        up = new QPushButton(centralWidget);
        up->setObjectName(QString::fromUtf8("up"));
        up->setGeometry(QRect(150, 310, 75, 23));
        flush = new QPushButton(centralWidget);
        flush->setObjectName(QString::fromUtf8("flush"));
        flush->setGeometry(QRect(380, 310, 75, 23));
        downimage = new QListWidget(centralWidget);
        downimage->setObjectName(QString::fromUtf8("downimage"));
        downimage->setGeometry(QRect(270, 70, 171, 201));
        upimage = new QListWidget(centralWidget);
        upimage->setObjectName(QString::fromUtf8("upimage"));
        upimage->setGeometry(QRect(40, 70, 171, 201));
        image = new QLabel(centralWidget);
        image->setObjectName(QString::fromUtf8("image"));
        image->setGeometry(QRect(3, 0, 591, 341));
        returned = new QPushButton(centralWidget);
        returned->setObjectName(QString::fromUtf8("returned"));
        returned->setGeometry(QRect(520, 320, 75, 23));
        clientClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(clientClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 600, 23));
        clientClass->setMenuBar(menuBar);
        mainToolBar = new QToolBar(clientClass);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        clientClass->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(clientClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        clientClass->setStatusBar(statusBar);

        retranslateUi(clientClass);

        QMetaObject::connectSlotsByName(clientClass);
    } // setupUi

    void retranslateUi(QMainWindow *clientClass)
    {
        clientClass->setWindowTitle(QCoreApplication::translate("clientClass", "clienttest", nullptr));
        login->setText(QCoreApplication::translate("clientClass", "\347\231\273\345\275\225", nullptr));
        select->setText(QCoreApplication::translate("clientClass", "\351\200\211\346\213\251\346\226\207\344\273\266", nullptr));
        registered->setText(QCoreApplication::translate("clientClass", "\346\263\250\345\206\214", nullptr));
        up->setText(QCoreApplication::translate("clientClass", "\344\270\212\344\274\240", nullptr));
        flush->setText(QCoreApplication::translate("clientClass", "\345\210\267\346\226\260", nullptr));
        image->setText(QString());
        returned->setText(QCoreApplication::translate("clientClass", "\350\277\224\345\233\236", nullptr));
    } // retranslateUi

};

namespace Ui {
    class clientClass: public Ui_clientClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CLIENT_H
