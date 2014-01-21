#include <QtGui>
#include <QtNetwork>

#include "account-mgr.h"
#include "seafile-applet.h"
#include "api/requests.h"
#include "login-dialog.h"

namespace {

const QString kDefaultUrl = "http://maxer.hu/getaddress.php";

} // namespace

LoginDialog::LoginDialog(QWidget *parent) : QDialog(parent)
{
    setupUi(this);
    setWindowTitle(tr("Add an account"));
    setWindowIcon(QIcon(":/images/seafile.png"));

    request_ = NULL;

    mStatusText->setText("");
    mLogo->setPixmap(QPixmap(":/images/seafile-32.png"));

    connect(mSubmitBtn, SIGNAL(clicked()), this, SLOT(doLogin()));

    const QRect screen = QApplication::desktop()->screenGeometry();
    move(screen.center() - this->rect().center());
}

void LoginDialog::doLogin()
{
    if (!validateInputs()) {
        return;
    }
    mStatusText->setText(tr("Logging in..."));

    disableInputs();

    QUrl url;
    url.setUrl(kDefaultUrl);
    url.addEncodedQueryItem("user", mUsername->text().toAscii());
    QNetworkRequest request;
    request.setUrl(url);

    manager_ = new QNetworkAccessManager(this);
    manager_->get(request);
    connect(manager_, SIGNAL(finished(QNetworkReply*)), this, SLOT(replyFinished(QNetworkReply*)));
}

void LoginDialog::disableInputs()
{
    mUsername->setEnabled(false);
    mPassword->setEnabled(false);
    mSubmitBtn->setEnabled(false);
}

void LoginDialog::enableInputs()
{
    mSubmitBtn->setEnabled(true);
    mUsername->setEnabled(true);
    mPassword->setEnabled(true);
}

void LoginDialog::onNetworkError(const QNetworkReply::NetworkError& error, const QString& error_string)
{
    showWarning(tr("Network Error:\n %1").arg(error_string));
    enableInputs();
}

void LoginDialog::onSslErrors(QNetworkReply* reply, const QList<QSslError>& errors)
{
    QString question = tr("<b>Warning:</b> The ssl certificate of this server is not trusted, proceed anyway?");
    if (QMessageBox::question(this,
                              getBrand(),
                              question,
                              QMessageBox::Yes | QMessageBox::No,
                              QMessageBox::No) == QMessageBox::Yes) {
        reply->ignoreSslErrors();
    }
}

void LoginDialog::replyFinished(QNetworkReply *reply)
{
    int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if ((reply->error() != QNetworkReply::NoError) || (code != 200)) {
        QMessageBox::warning(this, tr(SEAFILE_CLIENT_BRAND),
                             tr("Failed to get server address."),
                             QMessageBox::Ok);

        mSubmitBtn->setEnabled(true);
        mUsername->setEnabled(true);
        mPassword->setEnabled(true);

        mStatusText->setText("");
        return;
    }

    QByteArray data = reply->readAll();
    url_ = QUrl(QString(data.data()));


    if (url_.toString() == "unknown user") {
        QMessageBox::warning(this, tr(SEAFILE_CLIENT_BRAND),
                             tr("The user %1 doesn't exist.")
                             .arg(username_),
                             QMessageBox::Ok);

        mSubmitBtn->setEnabled(true);
        mUsername->setEnabled(true);
        mPassword->setEnabled(true);

        mStatusText->setText("");
        return;

    }

    if (request_) {
        delete request_;
    }

    request_ = new LoginRequest(url_, username_, password_);
    request_->setIgnoreSslErrors(false);

    connect(request_, SIGNAL(success(const QString&)),
            this, SLOT(loginSuccess(const QString&)));

    connect(request_, SIGNAL(failed(int)),
            this, SLOT(loginFailed(int)));

    connect(request_, SIGNAL(networkError(const QNetworkReply::NetworkError&, const QString&)),
                this, SLOT(onNetworkError(const QNetworkReply::NetworkError&, const QString&)));

    connect(request_, SIGNAL(sslErrors(QNetworkReply*, const QList<QSslError>&)),
            this, SLOT(onSslErrors(QNetworkReply*, const QList<QSslError>&)));

    request_->send();
}

bool LoginDialog::validateInputs()
{
    QString email = mUsername->text();
    if (email.size() == 0) {
        showWarning(tr("Please enter the username"));
        return false;
    }

    if (mPassword->text().size() == 0) {
        showWarning(tr("Please enter the password"));
        return false;
    }

    username_ = mUsername->text();
    password_ = mPassword->text();

    return true;
}

void LoginDialog::loginSuccess(const QString& token)
{
    Account account(url_, username_, token);
    if (seafApplet->accountManager()->saveAccount(account) < 0) {
        showWarning(tr("Failed to save current account"));
    } else {
        done(QDialog::Accepted);
    }
}

void LoginDialog::loginFailed(int code)
{
    QString err_msg, reason;
    if (code == 400) {
        reason = tr("Incorrect email or password");
    } else if (code == 500) {
        reason = tr("Internal Server Error");
    }

    if (reason.length() > 0) {
        err_msg = tr("Failed to login: %1").arg(reason);
    } else {
        err_msg = tr("Failed to login");
    }

    showWarning(err_msg);

    enableInputs();

    mStatusText->setText("");
}

void LoginDialog::showWarning(const QString& msg)
{
    seafApplet->warningBox(msg, this);
}
