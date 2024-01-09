// QtWidgetsApplication1.h
#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_QtWidgetsApplication1.h"
#include <QTextEdit>
#include <QComboBox>
#include <QLineEdit>
#include<QLabel>
class QtWidgetsApplication1 : public QMainWindow
{
    Q_OBJECT


public:
    QtWidgetsApplication1(QWidget* parent = nullptr);
    ~QtWidgetsApplication1();

    void updatePayload(QString sub, QString name, QString iat, QString admin);
    void updateSignature(QString algorithm, QString secretKey);
    QString cleanToken(const QString& token);
    

private:

    Ui::QtWidgetsApplication1Class ui;
    QTextEdit* token; 
    QLabel* errorMessageLabel;
  

private slots:
    void updateHeaderAlg(int index);
    void generateToken();



};
