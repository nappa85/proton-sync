#pragma once

#include <QByteArray>
#include <QString>

namespace Proton {
namespace CalendarIdentity {

inline QString calendarId(const QString &id) {
    return id.isEmpty() ? QStringLiteral("default") : id;
}

inline QString encoded(const QString &value) {
    return QString::fromLatin1(value.toUtf8().toBase64(
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

// Encode both components so wire UID separators cannot collide with the
// calendar namespace or the standalone recurrence suffix.
inline QString storedUid(const QString &account, const QString &calendar,
                         const QString &uid, qint64 recurrenceId = 0) {
    QString stored = QStringLiteral("proton-cal-%1-%2:%3")
        .arg(account, encoded(calendarId(calendar)), encoded(uid));
    if (recurrenceId > 0) stored += QStringLiteral("#%1").arg(recurrenceId);
    return stored;
}

inline QString rawUid(const QString &stored, const QString &account,
                      const QString &calendar) {
    QString prefix = QStringLiteral("proton-cal-%1-").arg(account);
    QString scopedPrefix = prefix + encoded(calendarId(calendar)) + QLatin1Char(':');
    if (stored.startsWith(scopedPrefix)) {
        QByteArray encodedUid = stored.mid(scopedPrefix.size()).section('#', 0, 0).toLatin1();
        return QString::fromUtf8(QByteArray::fromBase64(encodedUid, QByteArray::Base64UrlEncoding));
    }
    // Old account-only identities remain upload inputs until replacement
    // succeeds. Notebook IDs use "proton-calendar-", not this UID prefix.
    QString raw = stored.startsWith(prefix) ? stored.mid(prefix.size()) : stored;
    int hash = raw.lastIndexOf('#');
    bool ok = false;
    if (hash >= 0 && raw.mid(hash + 1).toLongLong(&ok) > 0 && ok) raw.truncate(hash);
    return raw;
}

} // namespace CalendarIdentity
} // namespace Proton
