// Proton account settings helper: explicit, user-confirmed purge of synced
// data (contacts collection + mKCal notebooks) for one account id.
// Mirrors the removal logic of the buteo sync plugin (proton_bridge_shim.cpp)
// but runs on demand from the Settings pulley menu instead of during sync.

#include "protonsettingsplugin.h"
#include "proton_log.h"

#include <QContactManager>
#include <QContactCollection>
#include <QContactCollectionFilter>
#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QLocale>
#include <QTimeZone>
#include <QTranslator>

#include <extendedcalendar.h>
#include <extendedstorage.h>
#include <notebook.h>
#include <KCalendarCore/Event>

static void purger_log(const QString &msg)
{
    proton_log(QStringLiteral("[settings-purge] ") + msg);
}

ProtonDataPurger::ProtonDataPurger(QObject *parent)
    : QObject(parent)
{
}

bool ProtonDataPurger::purgeData(int accountId)
{
    if (accountId <= 0) {
        purger_log(QStringLiteral("purgeData: invalid account id"));
        return false;
    }
    const QString id = QString::number(accountId);
    purger_log(QStringLiteral("purgeData: account ") + id);
    bool ok = true;

    // Contacts: remove our per-account collection (contacts go with it).
    {
        QtContacts::QContactManager manager(
            QStringLiteral("org.nemomobile.contacts.sqlite"));
        const QString remoteUid = QStringLiteral("proton-contacts-%1").arg(id);
        const QList<QtContacts::QContactCollection> collections = manager.collections();
        for (const QtContacts::QContactCollection &col : collections) {
            QVariantMap extended =
                col.metaData(QtContacts::QContactCollection::KeyExtended).toMap();
            if (extended.value(QStringLiteral("remote_uid")).toString() != remoteUid) {
                continue;
            }
            QtContacts::QContactCollectionFilter filter;
            filter.setCollectionId(col.id());
            const QList<QtContacts::QContact> contacts = manager.contacts(filter);
            if (!contacts.isEmpty()) {
                QList<QtContacts::QContactId> ids;
                ids.reserve(contacts.size());
                for (const QtContacts::QContact &c : contacts) {
                    ids.append(c.id());
                }
                QMap<int, QtContacts::QContactManager::Error> errorMap;
                manager.removeContacts(ids, &errorMap);
                purger_log(QStringLiteral("Removed %1 contacts from %2")
                               .arg(ids.size())
                               .arg(remoteUid));
            }
            if (!manager.removeCollection(col.id())) {
                purger_log(QStringLiteral("removeCollection failed ") + remoteUid);
                ok = false;
            } else {
                purger_log(QStringLiteral("Removed collection ") + remoteUid);
            }
        }
    }

    // Calendar: drop incidences, then erase our notebooks (current per-cal
    // ids plus the retired single per-account one).
    {
        mKCal::ExtendedCalendar::Ptr cal(
            new mKCal::ExtendedCalendar(QTimeZone::systemTimeZone()));
        mKCal::ExtendedStorage::Ptr storage =
            mKCal::ExtendedCalendar::defaultStorage(cal);
        if (!storage->open()) {
            purger_log(QStringLiteral("mKCal storage open failed"));
            return false;
        }
        const QString legacyUid = QStringLiteral("proton-calendar-%1").arg(id);
        const QString prefix = legacyUid + QLatin1Char('-');
        const mKCal::Notebook::List notebooks = storage->notebooks();
        for (const mKCal::Notebook::Ptr &nb : notebooks) {
            if (!nb) {
                continue;
            }
            if (nb->uid() != legacyUid && !nb->uid().startsWith(prefix)) {
                continue;
            }
            if (!storage->loadNotebookIncidences(nb->uid())) {
                purger_log(QStringLiteral("loadNotebookIncidences failed ") + nb->uid());
            }
            const KCalendarCore::Incidence::List existing = cal->incidences(nb->uid());
            for (const KCalendarCore::Incidence::Ptr &inc : existing) {
                KCalendarCore::Event::Ptr ev =
                    inc.dynamicCast<KCalendarCore::Event>();
                if (ev) {
                    cal->deleteEvent(ev);
                }
            }
            if (!storage->deleteNotebook(nb)) {
                purger_log(QStringLiteral("deleteNotebook failed ") + nb->uid());
                ok = false;
            } else {
                purger_log(QStringLiteral("Deleted notebook ") + nb->uid());
            }
        }
        if (!storage->save()) {
            purger_log(QStringLiteral("mKCal storage save failed"));
            ok = false;
        }
    }

    purger_log(QStringLiteral("purgeData done ok=") + (ok ? QStringLiteral("1") : QStringLiteral("0")));
    return ok;
}

void ProtonSettingsPlugin::registerTypes(const char *uri)
{
    qmlRegisterType<ProtonDataPurger>(uri, 1, 0, "ProtonDataPurger");
}

void ProtonSettingsPlugin::initializeEngine(QQmlEngine *engine, const char *uri)
{
    Q_UNUSED(engine);
    Q_UNUSED(uri);
    // One translator per process (initializeEngine can run per import).
    // Tries full locale first (proton_it_IT.qm), then language
    // (proton_it.qm); English (and unmatched locales) fall back to the
    // qsTr() source strings with no file at all.
    static bool installed = false;
    if (installed) {
        return;
    }
    installed = true;
    const QString locale = QLocale::system().name();
    const QString dir = QStringLiteral("/usr/share/proton/translations");
    QTranslator *translator = new QTranslator();
    bool loaded = translator->load(QStringLiteral("proton_%1").arg(locale), dir);
    if (!loaded && locale.contains(QLatin1Char('_'))) {
        loaded = translator->load(
            QStringLiteral("proton_%1").arg(locale.section(QLatin1Char('_'), 0, 0)), dir);
    }
    if (loaded) {
        QCoreApplication::installTranslator(translator);
    } else {
        delete translator;
    }
}
