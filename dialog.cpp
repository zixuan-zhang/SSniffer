#include "dialog.h"
#include "ui_dialog.h"
#include<QTime>

#include "snifferthread.h"
#include "displaythread.h"
#include<string>
#include<QDebug>
#include<QByteArray>

using namespace std;

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
    /*Column Count: 7
     *  Number  SrcMac  DstMac  SrcIp   DstIp   Protocol    Length
     */
    ui->treeWidget->setColumnCount(7);
    ui->treeWidget->setHeaderLabels(QStringList()<<"Number"<<"SrcMac"<<"DstMac"<<"SrcIp"<<"DstIp"<<"Protocol"<<"Length");

    snifferThread = new SnifferThread(this);
    connect(snifferThread,SIGNAL(PackageExtracted(QString)),this,SLOT(OnPacketExtracted(QString)));
    connect(snifferThread,SIGNAL(PackageAnalyzed(QStringList)), this, SLOT(OnPacketAnalyzed(QStringList)));
}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::on_pushButton_clicked()
{
    filterRule = ui->lineEdit->text();
    ui->treeWidget->clear();
    ui->textBrowser->clear();
    qDebug()<<"Filter Rule is "<<filterRule;
    snifferThread->changeFilterString(filterRule);
    qDebug()<<"Starting snifferthread"<<endl;
    snifferThread->start();
}

void Dialog::OnPacketExtracted(QString data){
    QStringList dataList = data.split(",");
    AddRoot(dataList);
}

void Dialog::AddRoot(QStringList data)
{
    QTreeWidgetItem *root = new QTreeWidgetItem(ui->treeWidget);
    for(int i = 0; i < data.count(); i++){
        root->setText(i, data[i]);
    }
}

void Dialog::on_pushButton_2_clicked()
{
   snifferThread->closeSniffer();
}

void Dialog::on_pushButton_3_clicked()
{
    QString selectNumber = ui->treeWidget->currentItem()->text(0);
    snifferThread->analyze_packet(selectNumber.toInt());
}

void Dialog::OnPacketAnalyzed(QStringList dataList){
    QString data;
    QStringList frontData = dataList[0].split(",");
    QStringList desList = QStringList()<<"Number: "<<"SrcMac: "<<"DstMac: "<<"SrcIp: "<<"DstIp: "<<"Protocol: "<<"Length: ";
    for(int i = 0; i < frontData.count(); i++){
        data += desList[i] + frontData[i] + "\n";
    }
    for(int i = 1; i < dataList.count(); i++){
        data += dataList[i];
    }
    qDebug()<<"Analyzed Data Received. Data count is "<<dataList.count();
    ui->textBrowser->setText(data);
}
