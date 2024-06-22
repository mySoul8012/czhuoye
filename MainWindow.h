#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QLineEdit>
#include "ARPCap.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartButtonClicked();

private:
    QLineEdit *interfaceIDLineEdit;
    QLineEdit *logFileNameLineEdit;
    QPushButton *startButton;
    ARPCap *arpCap;
};

#endif // MAINWINDOW_H
