#include "MainWindow.h"
#include <QVBoxLayout>
#include <QLabel>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), arpCap(nullptr) {
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout *layout = new QVBoxLayout(centralWidget);

    QLabel *interfaceIDLabel = new QLabel("Interface ID:", this);
    interfaceIDLineEdit = new QLineEdit(this);
    layout->addWidget(interfaceIDLabel);
    layout->addWidget(interfaceIDLineEdit);

    QLabel *logFileNameLabel = new QLabel("Log File Name:", this);
    logFileNameLineEdit = new QLineEdit(this);
    layout->addWidget(logFileNameLabel);
    layout->addWidget(logFileNameLineEdit);

    startButton = new QPushButton("Start Capturing", this);
    layout->addWidget(startButton);

    connect(startButton, &QPushButton::clicked, this, &MainWindow::onStartButtonClicked);
}

MainWindow::~MainWindow() {
    if (arpCap) {
        delete arpCap;
    }
}

void MainWindow::onStartButtonClicked() {
    QString interfaceID = interfaceIDLineEdit->text();
    QString logFileName = logFileNameLineEdit->text();

    if (interfaceID.isEmpty() || logFileName.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Please enter both Interface ID and Log File Name.");
        return;
    }

    if (arpCap) {
        delete arpCap;
    }

    arpCap = new ARPCap(interfaceID.toStdString(), logFileName.toStdString());
    arpCap->startCapturing();
}
