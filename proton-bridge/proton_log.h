#ifndef PROTON_LOG_H
#define PROTON_LOG_H

#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFile>

// Resolve the local date on every write, including syncs crossing midnight.
// Shared by the sync plugins and the Settings data-purge helper.
inline void proton_log(const QString &msg)
{
    const QDateTime now = QDateTime::currentDateTime();
    const QString directory = QDir::homePath() + QStringLiteral("/Documents/ProtonSync");
    if (!QDir().mkpath(directory)) {
        qWarning() << "Could not create Proton sync log directory:" << directory;
    } else {
        const QString path = directory + QLatin1Char('/')
            + now.date().toString(QStringLiteral("yyyy-MM-dd")) + QStringLiteral(".log");
        QFile file(path);
        if (file.open(QIODevice::Append | QIODevice::Text)) {
            const QByteArray line = (now.toString(Qt::ISODate) + QLatin1Char(' ')
                                     + msg + QLatin1Char('\n')).toUtf8();
            if (file.write(line) != line.size()) {
                qWarning() << "Could not write Proton sync log:" << path << file.errorString();
            }
        } else {
            qWarning() << "Could not open Proton sync log:" << path << file.errorString();
        }
    }
    qDebug() << msg;
}

#endif // PROTON_LOG_H
