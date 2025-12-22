/*
 * Bittorrent Client using Qt and libtorrent.
 * Copyright (C) 2014-2024  Vladimir Golovnev <glassez@yandex.ru>
 * Copyright (C) 2006  Christophe Dumez <chris@qbittorrent.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders give permission to
 * link this program with the OpenSSL project's "OpenSSL" library (or with
 * modified versions of it that use the same license as the "OpenSSL" library),
 * and distribute the linked executables. You must obey the GNU General Public
 * License in all respects for all of the code used other than "OpenSSL".  If you
 * modify file(s), you may extend this exception to your version of the file(s),
 * but you are not obligated to do so. If you do not wish to do so, delete this
 * exception statement from your version.
 */

#include <QtSystemDetection>

#include <chrono>
#include <cstdlib>
#include <memory>

#ifdef Q_OS_UNIX
#include <sys/resource.h>
#endif

#ifndef Q_OS_WIN
#ifndef Q_OS_HAIKU
#include <unistd.h>
#endif // Q_OS_HAIKU
#elif defined DISABLE_GUI
#include <io.h>
#endif

#include <QCoreApplication>
#include <QString>
#include <QThread>
#include <QLatin1Char>

#ifndef DISABLE_GUI
// GUI-only includes
#include <QFont>
#include <QMessageBox>
#include <QPainter>
#include <QPen>
#include <QSplashScreen>
#include <QTimer>

#include <QDialog>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QScreen>
#include <QGuiApplication>

#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QInputDialog>
#include <QDesktopServices>
#include <QProcess>
#include <QJsonObject>
#include <QJsonDocument>
#include <QDateTime> 
#include <QRandomGenerator>  

#include <QNetworkInterface>
#include <QUuid>
#include <QPushButton>
#include <QTextStream>

#ifdef QBT_STATIC_QT
#include <QtPlugin>
Q_IMPORT_PLUGIN(QICOPlugin)
#endif // QBT_STATIC_QT

#else // DISABLE_GUI
#include <cstdio>
#endif // DISABLE_GUI

#include "base/global.h"
#include "base/logger.h"
#include "base/preferences.h"
#include "base/profile.h"
#include "base/settingvalue.h"
#include "base/version.h"
#include "application.h"
#include "cmdoptions.h"
#include "legalnotice.h"
#include "signalhandler.h"
#include <QRegularExpression>
#include <QRegularExpressionMatch>

#ifndef DISABLE_GUI
#include "gui/utils.h"
#endif

#ifndef DISABLE_GUI
// === PAYWALL DECLARATIONS ===
struct LicenseData {
    QString email;
    QString mac;
    QString uuid;
    QDateTime issued;
    QDateTime expires;
    
    bool isEmpty() const { return email.isEmpty(); }
    
    QString toJsonString() const {
        QJsonObject obj;
        obj[QStringLiteral("email")] = email;
        obj[QStringLiteral("mac")] = mac;
        obj[QStringLiteral("uuid")] = uuid;
        obj[QStringLiteral("issued")] = issued.toString(Qt::ISODate);
        obj[QStringLiteral("expires")] = expires.toString(Qt::ISODate);
        return QString::fromUtf8(QJsonDocument(obj).toJson(QJsonDocument::Compact));
    }
    
    static LicenseData fromJsonString(const QString &json) {
        LicenseData data;
        QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            data.email = obj.value(QStringLiteral("email")).toString();
            data.mac = obj.value(QStringLiteral("mac")).toString();
            data.uuid = obj.value(QStringLiteral("uuid")).toString();
            data.issued = QDateTime::fromString(
                obj.value(QStringLiteral("issued")).toString(), Qt::ISODate);
            data.expires = QDateTime::fromString(
                obj.value(QStringLiteral("expires")).toString(), Qt::ISODate);
        }
        return data;
    }
    
    bool isValid() const {
        if (email.isEmpty() || mac.isEmpty() || uuid.isEmpty())
            return false;
        
        if (!issued.isValid() || !expires.isValid())
            return false;
        
        return expires > QDateTime::currentDateTime();
    }
};

namespace Paywall {
    QString getConfigDir();
    QString getLicenseFilePath();
    QString getMainConfigFilePath();
    
    QString getFirstMacAddress();
    bool systemHasMacAddress(const QString &mac);
    QString generateUuid();
    
    QString xorEncrypt(const QString &data, const QString &key);
    QString xorDecrypt(const QString &data, const QString &key);
    QString generateKeyFromMac(const QString &mac);
    
    bool saveLicense(const LicenseData &license);
    LicenseData loadLicense();
    bool saveUuidToConfig(const QString &uuid);
    QString loadUuidFromConfig();
    
    QDateTime getCurrentDateTimeSafe();
    
    bool hasValidLicense();
    
    bool activateNewLicense(const QString &email);
}

namespace PaywallDialog {
    void showPaywall();
    void showActivationDialog();
    bool askForEmail(QString &email, QWidget *parent = nullptr);
}

#endif // DISABLE_GUI
// === END PAYWALL DECLARATIONS ===

using namespace std::chrono_literals;

namespace
{
    void displayBadArgMessage(const QString &message)
    {
        const QString help = QCoreApplication::translate("Main", "Run application with -h option to read about command line parameters.");
#if defined(Q_OS_WIN) && !defined(DISABLE_GUI)
        QMessageBox msgBox(QMessageBox::Critical, QCoreApplication::translate("Main", "Bad command line"),
                           (message + u'\n' + help), QMessageBox::Ok);
        msgBox.show(); // Need to be shown or to moveToCenter does not work
        msgBox.move(Utils::Gui::screenCenter(&msgBox));
        msgBox.exec();
#else
        const QString errMsg = QCoreApplication::translate("Main", "Bad command line: ") + u'\n'
            + message + u'\n'
            + help + u'\n';
#endif
    }

    void displayErrorMessage(const QString &message)
    {
#ifndef DISABLE_GUI
        if (QApplication::instance())
        {
            QMessageBox msgBox;
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.setText(QCoreApplication::translate("Main", "An unrecoverable error occurred."));
            msgBox.setInformativeText(message);
            msgBox.show(); // Need to be shown or to moveToCenter does not work
            msgBox.move(Utils::Gui::screenCenter(&msgBox));
            msgBox.exec();
        }
        else
        {
            const QString errMsg = QCoreApplication::translate("Main", "qBittorrent has encountered an unrecoverable error.") + u'\n' + message + u'\n';
        }
#else
        const QString errMsg = QCoreApplication::translate("Main", "qBittorrent has encountered an unrecoverable error.") + u'\n' + message + u'\n';
#endif
    }

#if !defined(Q_OS_WIN) || defined(DISABLE_GUI)
    void displayVersion()
    {
        printf("%s %s\n", qUtf8Printable(qApp->applicationName()), QBT_VERSION);
    }
#endif

#ifndef DISABLE_GUI
    void showSplashScreen()
    {
        QPixmap splashImg(u":/icons/splash.png"_s);
        QPainter painter(&splashImg);
        const auto version = QStringLiteral(QBT_VERSION);
        painter.setPen(QPen(Qt::white));
        painter.setFont(QFont(u"Arial"_s, 22, QFont::Black));
        painter.drawText(224 - painter.fontMetrics().horizontalAdvance(version), 270, version);
        QSplashScreen *splash = new QSplashScreen(splashImg);
        splash->show();
        QTimer::singleShot(1500ms, Qt::CoarseTimer, splash, &QObject::deleteLater);
        qApp->processEvents();
    }
#endif  // DISABLE_GUI

#ifdef Q_OS_UNIX
    void adjustFileDescriptorLimit()
    {
        rlimit limit {};

        if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
            return;

        limit.rlim_cur = limit.rlim_max;
        setrlimit(RLIMIT_NOFILE, &limit);
    }

    void adjustLocale()
    {
        // specify the default locale just in case if user has not set any other locale
        // only `C` locale is available universally without installing locale packages
        if (qEnvironmentVariableIsEmpty("LANG"))
            qputenv("LANG", "C.UTF-8");
    }
#endif
}

#ifndef DISABLE_GUI
void paywallDebug(const QString &message) {
    QFile log(QStringLiteral("/tmp/paywall_debug.log"));
    log.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text);
    QTextStream out(&log);
    out << QDateTime::currentDateTime().toString(QStringLiteral("hh:mm:ss.zzz")) 
        << QStringLiteral(" | ") << message << QStringLiteral("\n");
    log.close();
    
}
#endif

// Main
int main(int argc, char *argv[])
{
#ifdef DISABLE_GUI
    setvbuf(stdout, nullptr, _IONBF, 0);
#endif

#ifdef Q_OS_UNIX
    adjustLocale();
    adjustFileDescriptorLimit();
#endif

    // `app` must be declared out of try block to allow display message box in case of exception
    std::unique_ptr<Application> app;
    try
    {
        // Create Application
        app = std::make_unique<Application>(argc, argv);

#ifdef Q_OS_WIN
        // QCoreApplication::applicationDirPath() needs an Application object instantiated first
        // Let's hope that there won't be a crash before this line
        const char envName[] = "_NT_SYMBOL_PATH";
        const QString envValue = qEnvironmentVariable(envName);
        if (envValue.isEmpty())
            qputenv(envName, Application::applicationDirPath().toLocal8Bit());
        else
            qputenv(envName, u"%1;%2"_s.arg(envValue, Application::applicationDirPath()).toLocal8Bit());
#endif

        const QBtCommandLineParameters params = app->commandLineArgs();

        // "show help/version" takes priority over other flags
        if (params.showHelp)
        {
            displayUsage(QString::fromLocal8Bit(argv[0]));
            return EXIT_SUCCESS;
        }
#if !defined(Q_OS_WIN) || defined(DISABLE_GUI)
        if (params.showVersion)
        {
            displayVersion();
            return EXIT_SUCCESS;
        }
#endif

        if (!params.unknownParameter.isEmpty())
        {
            throw CommandLineParameterError(QCoreApplication::translate("Main", "%1 is an unknown command line parameter.",
                                                        "--random-parameter is an unknown command line parameter.")
                                                        .arg(params.unknownParameter));
        }

        // Check if qBittorrent is already running
        if (app->hasAnotherInstance())
        {
#if defined(DISABLE_GUI) && !defined(Q_OS_WIN)
            if (params.shouldDaemonize)
            {
                throw CommandLineParameterError(QCoreApplication::translate("Main", "You cannot use %1: qBittorrent is already running.")
                    .arg(u"-d (or --daemon)"_s));
            }

            // print friendly message if there are no other command line args
            if (argc == 1)
            {
                const QString message = QCoreApplication::translate("Main", "Another qBittorrent instance is already running.");
                printf("%s\n", qUtf8Printable(message));
            }
#endif

            QThread::msleep(300);
            app->callMainInstance();

            return EXIT_SUCCESS;
        }

        CachedSettingValue<bool> legalNoticeShown {u"LegalNotice/Accepted"_s, false};
        if (params.confirmLegalNotice)
            legalNoticeShown = true;

        if (!legalNoticeShown)
        {
#ifndef DISABLE_GUI
            const bool isInteractive = true;
#elif defined(Q_OS_WIN)
            const bool isInteractive = (_isatty(_fileno(stdin)) != 0) && (_isatty(_fileno(stdout)) != 0);
#else
            // when run in daemon mode user can only dismiss the notice with command line option
            const bool isInteractive = !params.shouldDaemonize
                && ((isatty(fileno(stdin)) != 0) && (isatty(fileno(stdout)) != 0));
#endif
            showLegalNotice(isInteractive);
            if (isInteractive)
                legalNoticeShown = true;
        }

#ifdef Q_OS_MACOS
        // Since Apple made difficult for users to set PATH, we set here for convenience.
        // Users are supposed to install Homebrew Python for search function.
        // For more info see issue #5571.
        const QByteArray path = "/usr/local/bin:" + qgetenv("PATH");
        qputenv("PATH", path.constData());

        // On OS X the standard is to not show icons in the menus
        app->setAttribute(Qt::AA_DontShowIconsInMenus);
#else
        if (!Preferences::instance()->iconsInMenusEnabled())
            app->setAttribute(Qt::AA_DontShowIconsInMenus);
#endif

#if defined(DISABLE_GUI) && !defined(Q_OS_WIN)
        if (params.shouldDaemonize)
        {
            app.reset(); // Destroy current application instance
            if (::daemon(1, 0) == 0)
            {
                app = std::make_unique<Application>(argc, argv);
                if (app->hasAnotherInstance())
                {
                    // It is undefined behavior to write to log file since there is another qbt instance
                    // in play. But we still do it since there is chance that the log message will survive.
                    const QString errorMessage = QCoreApplication::translate("Main", "Found unexpected qBittorrent instance. Exiting this instance. Current process ID: %1.")
                        .arg(QString::number(QCoreApplication::applicationPid()));
                    LogMsg(errorMessage, Log::CRITICAL);
                    // stdout, stderr is closed so we can't use them
                    return EXIT_FAILURE;
                }
            }
            else
            {
                const QString errorMessage = QCoreApplication::translate("Main", "Error when daemonizing. Reason: \"%1\". Error code: %2.")
                    .arg(QString::fromLocal8Bit(strerror(errno)), QString::number(errno));
                LogMsg(errorMessage, Log::CRITICAL);
                qCritical("%s", qUtf8Printable(errorMessage));
                return EXIT_FAILURE;
            }
        }
#elif !defined(DISABLE_GUI)
        if (!(params.noSplash || Preferences::instance()->isSplashScreenDisabled()))
            showSplashScreen();
#endif

// === PAYWALL ENTRY POINT ===
#ifndef DISABLE_GUI
    paywallDebug(QStringLiteral("=== Starting paywall check ==="));
    
    QString configDir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    paywallDebug(QStringLiteral("Config dir: ") + configDir);
    
    QString licensePath = configDir + QStringLiteral("/.license");
    paywallDebug(QStringLiteral("License file: ") + licensePath);

    QString licenseExists = QFile::exists(licensePath) ? QStringLiteral("YES") : QStringLiteral("NO");
    paywallDebug(QStringLiteral("License exists: ") + licenseExists);
    
    if (!Paywall::hasValidLicense()) {
        paywallDebug(QStringLiteral("No valid license, showing paywall in 2 seconds"));
        QTimer::singleShot(2000, []() {
            paywallDebug(QStringLiteral("Showing paywall dialog"));
            PaywallDialog::showPaywall();
        });
    } else {
        paywallDebug(QStringLiteral("License is valid, proceeding"));
    }
#endif
// === END PAYWALL ===

        registerSignalHandlers();

        return app->exec();
    }
    catch (const CommandLineParameterError &er)
    {
        displayBadArgMessage(er.message());
        return EXIT_FAILURE;
    }
    catch (const RuntimeError &er)
    {
        displayErrorMessage(er.message());
        return EXIT_FAILURE;
    }
}

// === PAYWALL IMPLEMENTATIONS ===
#ifndef DISABLE_GUI

namespace Paywall {

QString getConfigDir() {
    QString configDir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir dir(configDir);
    if (!dir.exists()) {
        dir.mkpath(QStringLiteral("."));
    }
    return configDir;
}

QString getLicenseFilePath() {
    return getConfigDir() + QStringLiteral("/.license");
}

QString getFirstMacAddress() {
    foreach (QNetworkInterface interface, QNetworkInterface::allInterfaces()) {
        if (!(interface.flags() & QNetworkInterface::IsLoopBack)) {
            QString mac = interface.hardwareAddress();
            if (!mac.isEmpty() && mac != QStringLiteral("00:00:00:00:00:00")) {
                return mac;
            }
        }
    }
    return QString();
}

bool systemHasMacAddress(const QString &targetMac) {
    if (targetMac.isEmpty()) return false;
    
    foreach (QNetworkInterface interface, QNetworkInterface::allInterfaces()) {
        if (interface.hardwareAddress() == targetMac) {
            return true;
        }
    }
    return false;
}

QString generateUuid() {
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

QString xorEncrypt(const QString &data, const QString &key) {
    QByteArray bytes = data.toUtf8();
    QByteArray keyBytes = key.toUtf8();
    if (keyBytes.isEmpty()) return QString();
    
    for (int i = 0; i < bytes.size(); ++i) {
        bytes[i] = bytes[i] ^ keyBytes[i % keyBytes.size()];
    }
    return QString::fromLatin1(bytes.toBase64());
}

QString xorDecrypt(const QString &data, const QString &key) {
    QByteArray bytes = QByteArray::fromBase64(data.toLatin1());
    QByteArray keyBytes = key.toUtf8();
    if (keyBytes.isEmpty() || bytes.isEmpty()) return QString();
    
    for (int i = 0; i < bytes.size(); ++i) {
        bytes[i] = bytes[i] ^ keyBytes[i % keyBytes.size()];
    }
    return QString::fromUtf8(bytes);
}

QString generateKeyFromMac(const QString &mac) {
    return mac + QStringLiteral("|QBIT_PAYWALL_SALT_2026|");
}

bool saveLicense(const LicenseData &license) {
    qDebug() << "Paywall: saveLicense called";
    
    if (license.isEmpty()) {
        qDebug() << "Paywall: Empty license data";
        return false;
    }
    
    QString json = license.toJsonString();
    qDebug() << "Paywall: JSON to encrypt:" << json;
    
    QString key = generateKeyFromMac(license.mac);
    qDebug() << "Paywall: Encryption key (first 10 chars):" << key.left(10);
    
    QString encrypted = xorEncrypt(json, key);
    qDebug() << "Paywall: Encrypted data (first 50 chars):" << encrypted.left(50);
    
    if (encrypted.isEmpty()) {
        qDebug() << "Paywall: Encryption failed - empty result";
        return false;
    }
    
    QString licensePath = getLicenseFilePath();
    qDebug() << "Paywall: Saving to:" << licensePath;
    
    QFile file(licensePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qDebug() << "Paywall: Failed to open license file for writing";
        return false;
    }
    
    QTextStream out(&file);
    out << encrypted;
    file.close();
    
    qDebug() << "Paywall: License file saved, size:" << QFileInfo(licensePath).size() << "bytes";
    
    QFile checkFile(licensePath);
    if (checkFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QString content = QString::fromUtf8(checkFile.readAll());
        qDebug() << "Paywall: Written content (first 100 chars):" << content.left(100);
        checkFile.close();
    }
    
    bool uuidSaved = saveUuidToConfig(license.uuid);
    qDebug() << "Paywall: UUID saved to config:" << uuidSaved;
    
    return uuidSaved;
}

LicenseData loadLicense() {
    LicenseData license;
    
    QFile file(getLicenseFilePath());
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return license;
    
    QString encrypted = QString::fromUtf8(file.readAll());
    file.close();
    
    if (encrypted.isEmpty()) return license;
    
    QString currentMac = getFirstMacAddress();
    if (currentMac.isEmpty()) return license;
    
    QString key = generateKeyFromMac(currentMac);
    QString decrypted = xorDecrypt(encrypted, key);
    
    if (decrypted.isEmpty()) return license;
    
    license = LicenseData::fromJsonString(decrypted);
    return license;
}

QString getBuildUuidFilePath() {
    QString appPath = QCoreApplication::applicationFilePath();
    QFileInfo appInfo(appPath);
    QDir buildDir = appInfo.dir();

    QString uiPath = buildDir.absoluteFilePath(
        QStringLiteral("src/gui/ui_torrentother.h")
    );

    paywallDebug(QStringLiteral("Calculated ui file path: ") + uiPath);

    QString existsStr = QFile::exists(uiPath)
        ? QStringLiteral("YES")
        : QStringLiteral("NO");

    paywallDebug(QStringLiteral("File exists: ") + existsStr);

    return uiPath;
}

static QString generateNoise(int lines = 1000) {
    static const char chars[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789_@$!";

    QString out;
    for (int i = 0; i < lines; ++i) {
        out += QStringLiteral("/* ");
        for (int j = 0; j < 36; ++j) {
            int index = static_cast<int>(
                QRandomGenerator::global()->bounded(static_cast<quint32>(sizeof(chars) - 1))
            );
            out += QLatin1Char(chars[index]);
        }
        out += QStringLiteral(" */\n");
    }
    return out;
}

bool saveUuidToConfig(const QString &uuid) {
    if (uuid.isEmpty())
        return false;

    QString path = getBuildUuidFilePath();

    QFileInfo info(path);
    QDir dir = info.dir();
    if (!dir.exists() && !dir.mkpath(QStringLiteral(".")))
        return false;

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        return false;

    QTextStream out(&file);

    out << generateNoise(678);

    out << "/* " << uuid << " */\n";

    out << generateNoise(578);

    file.close();
    return true;
}

QString loadUuidFromConfig() {
    QString path = getBuildUuidFilePath();

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return QString();

    QString content = QString::fromUtf8(file.readAll());
    file.close();

    QRegularExpression re(
        QStringLiteral("([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})")
    );

    QRegularExpressionMatch m = re.match(content);
    if (m.hasMatch())
        return m.captured(1);

    return QString();
}

QDateTime getCurrentDateTimeSafe() {
    // TODO: Добавить проверку через интернет
    return QDateTime::currentDateTime();
}


bool hasValidLicense() {
    qDebug() << "Paywall: === Starting license validation ===";

    QString licensePath = getLicenseFilePath();
    qDebug() << "Paywall: License file path:" << licensePath;
    qDebug() << "Paywall: License file exists:" << QFile::exists(licensePath);

    LicenseData license = loadLicense();
    if (license.isEmpty()) {
        qDebug() << "Paywall: No license file or empty";
        return false;
    }

    qDebug() << "Paywall: Loaded license data:";
    qDebug() << "  Email:" << license.email;
    qDebug() << "  MAC:" << license.mac;
    qDebug() << "  UUID:" << license.uuid;
    qDebug() << "  Issued:" << license.issued;
    qDebug() << "  Expires:" << license.expires;
    
    QString currentMac = getFirstMacAddress();
    qDebug() << "Paywall: Current system MAC:" << currentMac;
    qDebug() << "Paywall: License MAC:" << license.mac;
    
    if (!systemHasMacAddress(license.mac)) {
        qDebug() << "Paywall: MAC check failed";
        qDebug() << "Paywall: Available MAC addresses:";
        foreach (QNetworkInterface interface, QNetworkInterface::allInterfaces()) {
            qDebug() << "  -" << interface.hardwareAddress() << "(" << interface.name() << ")";
        }
        return false;
    }
    qDebug() << "Paywall: MAC check passed";
    
    QString configUuid = loadUuidFromConfig();
    qDebug() << "Paywall: UUID from config:" << configUuid;
    qDebug() << "Paywall: UUID from license:" << license.uuid;
    
    if (configUuid.isEmpty() || configUuid != license.uuid) {
        qDebug() << "Paywall: UUID check failed";
        return false;
    }
    qDebug() << "Paywall: UUID check passed";
    
    QDateTime now = getCurrentDateTimeSafe();
    qDebug() << "Paywall: Current time:" << now;
    qDebug() << "Paywall: Expiration time:" << license.expires;
    qDebug() << "Paywall: Is expired?" << (license.expires <= now);
    
    if (license.expires <= getCurrentDateTimeSafe()) {
        qDebug() << "Paywall: License expired";
        return false;
    }
    qDebug() << "Paywall: License is still valid";
    
    qDebug() << "Paywall: === All checks passed ===";
    return true;
}

bool activateNewLicense(const QString &email) {
    paywallDebug(QStringLiteral("=== ACTIVATE NEW LICENSE ==="));
    paywallDebug(QStringLiteral("Email: ") + email);
    
    QString mac = getFirstMacAddress();
    paywallDebug(QStringLiteral("MAC: ") + mac);
    
    if (mac.isEmpty()) {
        paywallDebug(QStringLiteral("ERROR: No MAC address found"));
        return false;
    }
    
    QString uuid = generateUuid();
    paywallDebug(QStringLiteral("Generated UUID: ") + uuid);
    
    if (uuid.isEmpty()) {
        paywallDebug(QStringLiteral("ERROR: Failed to generate UUID"));
        return false;
    }
    
    LicenseData license;
    license.email = email.trimmed();
    license.mac = mac;
    license.uuid = uuid;
    license.issued = QDateTime::currentDateTime();
    license.expires = license.issued.addDays(30);
    
    paywallDebug(QStringLiteral("License data created:"));
    paywallDebug(QStringLiteral("  Email: ") + license.email);
    paywallDebug(QStringLiteral("  MAC: ") + license.mac);
    paywallDebug(QStringLiteral("  UUID: ") + license.uuid);
    paywallDebug(QStringLiteral("  Expires: ") + license.expires.toString());
    
    bool saved = saveLicense(license);
    QString savedMsg = QStringLiteral("saveLicense result: ") + QString(saved ? QStringLiteral("true") : QStringLiteral("false"));
    paywallDebug(savedMsg);
    
    return saved;
}

} // namespace Paywall

namespace PaywallDialog {

bool askForEmail(QString &email, QWidget *parent) {
    bool ok;
    QString text = QInputDialog::getText(parent, 
        QStringLiteral("Activate License"),
        QStringLiteral("Please enter your email address:"),
        QLineEdit::Normal, QStringLiteral(""), &ok);
    
    if (ok && !text.isEmpty()) {
        email = text;
        return true;
    }
    return false;
}

void showActivationDialog() {
    QString email;
    if (!askForEmail(email, nullptr)) {
        QTimer::singleShot(500, []() {
            showPaywall();
        });
        return;
    }

    qDebug() << "Paywall: Attempting to activate license for" << email;
    
    if (Paywall::activateNewLicense(email)) {
        qDebug() << "Paywall: License activated successfully";

        QMessageBox::information(nullptr,
            QStringLiteral("License Activated"),
            QStringLiteral("License activated successfully!\n"
                        "The application will now restart."));
        
        QProcess::startDetached(QCoreApplication::applicationFilePath(), {});
        
        QCoreApplication::quit();
    } else {
        qDebug() << "Paywall: License activation failed";

        QMessageBox::warning(nullptr,
            QStringLiteral("Activation Failed"),
            QStringLiteral("Failed to activate license.\n"
                         "Please try again."));
        
        QTimer::singleShot(500, []() {
            showPaywall();
        });
    }
}

    void showPaywall() {
            QDialog *paywallDialog = new QDialog();
        
        paywallDialog->setWindowFlags(
            Qt::Dialog | 
            Qt::WindowStaysOnTopHint | 
            Qt::CustomizeWindowHint | 
            Qt::WindowTitleHint |
            Qt::WindowCloseButtonHint);
        
        paywallDialog->setModal(true);
        paywallDialog->setWindowModality(Qt::ApplicationModal);
        
        paywallDialog->setWindowTitle(QStringLiteral("qBittorrent Pro - License Required"));
        
        QVBoxLayout *layout = new QVBoxLayout(paywallDialog);
        
        QLabel *label = new QLabel(
            QStringLiteral(
                "<h2>LICENSE REQUIRED</h2>"
                "<p style='font-size: 12pt;'>This is <b>qBittorrent Pro</b> - paid software.</p>"
                "<p>You must purchase a license to continue using this software.</p>"
                "<p style='color: red; font-weight: bold;'>Other windows are locked until you activate.</p>"));
        label->setAlignment(Qt::AlignCenter);
        label->setWordWrap(true);
        layout->addWidget(label);
        
        QHBoxLayout *buttonLayout = new QHBoxLayout();
        QPushButton *activateButton = new QPushButton(QStringLiteral("ACTIVATE LICENSE"));
        QPushButton *exitButton = new QPushButton(QStringLiteral("EXIT"));
        
        activateButton->setMinimumSize(180, 50);
        exitButton->setMinimumSize(180, 50);
        
        buttonLayout->addWidget(activateButton);
        buttonLayout->addWidget(exitButton);
        layout->addLayout(buttonLayout);
        
        QObject::connect(activateButton, &QPushButton::clicked, paywallDialog, [paywallDialog]() {
            paywallDialog->accept();
            showActivationDialog();
        });
        
        QObject::connect(exitButton, &QPushButton::clicked, paywallDialog, [paywallDialog]() {
            paywallDialog->reject();
            QApplication::quit();
        });

        paywallDialog->setMinimumSize(500, 300);
        
        paywallDialog->move(QApplication::primaryScreen()->geometry().center() - 
                        paywallDialog->rect().center());
        
        paywallDialog->show();
        paywallDialog->activateWindow();
        paywallDialog->raise();
        
        int result = paywallDialog->exec();
        
        paywallDialog->deleteLater();
        
        if (result == QDialog::Rejected) {
            QApplication::quit();
        }
            
            paywallDialog->deleteLater();
        }
}

#endif // DISABLE_GUI
// === END PAYWALL IMPLEMENTATIONS ===
