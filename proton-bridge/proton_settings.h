#ifndef PROTON_SETTINGS_H
#define PROTON_SETTINGS_H

#include <QJsonObject>
#include <QSettings>
#include <QStringList>

// Plugin state (QSettings proton/sync-tokens) as an opaque string store:
// the Rust side reads every group and decides what to write. Shared by the
// sync and SignOn plugins.

inline QJsonObject proton_settings_load()
{
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    QJsonObject groups;
    const QStringList names = settings.childGroups();
    for (const QString &group : names) {
        settings.beginGroup(group);
        QJsonObject keys;
        const QStringList childKeys = settings.childKeys();
        for (const QString &key : childKeys) {
            keys.insert(key, settings.value(key).toString());
        }
        settings.endGroup();
        groups.insert(group, keys);
    }
    return groups;
}

// {group: {key: "value" | null}}: null removes the key. Applied key by
// key, so concurrent writers of other keys are never clobbered.
inline void proton_settings_apply(const QJsonObject &patch)
{
    if (patch.isEmpty()) {
        return;
    }
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    for (auto group = patch.constBegin(); group != patch.constEnd(); ++group) {
        settings.beginGroup(group.key());
        const QJsonObject keys = group.value().toObject();
        for (auto key = keys.constBegin(); key != keys.constEnd(); ++key) {
            if (key.value().isNull()) {
                settings.remove(key.key());
            } else {
                settings.setValue(key.key(), key.value().toString());
            }
        }
        settings.endGroup();
    }
    settings.sync();
}

#endif // PROTON_SETTINGS_H
