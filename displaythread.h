#ifndef DISPLAYTHREAD_H
#define DISPLAYTHREAD_H

#include <QThread>
#include<QStringList>

class displaythread : public QThread
{
    Q_OBJECT
public:
    explicit displaythread(QObject *parent = 0);

signals:
    void DataSend(QStringList);

public slots:
    void run();

};

#endif // DISPLAYTHREAD_H
