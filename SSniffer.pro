#-------------------------------------------------
#
# Project created by QtCreator 2014-10-16T15:01:05
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = SSniffer
TEMPLATE = app


SOURCES += main.cpp\
        dialog.cpp \
    snifferthread.cpp

HEADERS  += dialog.h \
    snifferthread.h

FORMS    += dialog.ui

INCLUDEPATH += /usr/include


LIBS += -L /usr/lib/x86_64-linux-gnu -lpcap
