#ifndef DIALOG_H
#define DIALOG_H
#include"snifferthread.h"
#include <QDialog>
#include <QQueue>
#include<QTreeWidgetItem>

namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = 0);
    ~Dialog();

private slots:
    void on_pushButton_clicked();
    void OnPacketExtracted(QString data);
    void OnPacketAnalyzed(QStringList dataList);

    void on_pushButton_2_clicked();

    void on_pushButton_3_clicked();


private:
    Ui::Dialog *ui;
    QString filterRule;
    void AddRoot(QStringList data);

    SnifferThread *snifferThread;
};

#endif // DIALOG_H
