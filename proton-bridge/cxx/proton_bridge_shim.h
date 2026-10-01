#pragma once

#include "ClientPlugin.h"
#include "SyncPluginLoader.h"

#include <QContactManager>
#include <QContact>
#include <QContactDetail>
#include <QContactName>
#include <QContactPhoneNumber>
#include <QContactEmailAddress>
#include <QContactAddress>
#include <QContactOrganization>
#include <QContactNote>
#include <QContactAvatar>
#include <QContactCollection>
#include <QContactCollectionId>
#include <QContactGuid>
#include <QContactTimestamp>
#include <QContactSyncTarget>
#include <QContactDisplayLabel>
#include <QContactDetailFilter>
#include <QContactCollectionFilter>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>
#include <QSettings>

#include <QContactBirthday>
#include <QContactNickname>
#include <QContactUrl>
#include <QContactGender>
#include <QContactAnniversary>
#include <QContactTimestamp>
#include <extendedcalendar.h>
#include <extendedstorage.h>
#include <notebook.h>
#include <sqlitestorage.h>
#include <KCalendarCore/Event>
#include <KCalendarCore/Recurrence>
#include <KCalendarCore/RecurrenceRule>
#include <KCalendarCore/Attendee>
#include <KCalendarCore/Person>
#include <KCalendarCore/Alarm>

#include <Accounts/manager.h>
#include <Accounts/account.h>
#include <Accounts/account-service.h>
#include <Accounts/auth-data.h>
#include <Accounts/service.h>
#include <SignOn/identity.h>
#include <SignOn/identityinfo.h>
#include <SignOn/authsession.h>
#include <SignOn/sessiondata.h>
#include <SignOn/signonerror.h>

#include "proton_bridge.h"

namespace Proton {

class ProtonContactsPlugin : public Buteo::ClientPlugin
{
    Q_OBJECT

public:
    ProtonContactsPlugin(const QString &aPluginName,
                         const Buteo::SyncProfile &aProfile,
                         Buteo::PluginCbInterface *aCbInterface);
    ~ProtonContactsPlugin() override;

    bool init() override;
    bool uninit() override;
    bool startSync() override;
    void abortSync(Sync::SyncStatus aStatus = Sync::SYNC_ABORTED) override;
    bool cleanUp() override;
    Buteo::SyncResults getSyncResults() const override;

public slots:
    void connectivityStateChanged(Sync::ConnectivityType aType, bool aState) override;

private slots:
    void pollStatus();
    void onSignOnResponse(const SignOn::SessionData &data);
    void onSignOnError(const SignOn::Error &error);

private:
    bool requestCredentials();
    bool writeContactsToQtPIM(const QByteArray &json);
    QtContacts::QContactCollection findOrCreateCollection();
    void persistTokens(const QString &refreshToken, const QString &uid);
    QPair<QString, QString> loadPersistedTokens();
    void persistContactsMaps(const QList<QtContacts::QContact> &saved);
    QJsonArray exportContactsInventory();
    void persistContactsAnchors(const QString &anchorsJson);
    QString loadContactsAnchors();
    QStringList loadContactsKnownUids();
    // Posted-but-unconfirmed creates ({qcontact_id: stable_uid}) for retry
    // idempotency. Persisted wholesale on EVERY run outcome (complete AND
    // error — the error path is exactly when entries exist); an empty
    // value clears stale entries, never merges.
    void persistContactsPending(const QString &pendingJson);

    ProtonSyncEngine *m_engine = nullptr;
    QTimer *m_timer = nullptr;
    QtContacts::QContactManager *m_manager = nullptr;
    QString m_accountId;
    Accounts::Manager *m_accountManager = nullptr;
    Accounts::AccountService *m_accountService = nullptr;
    SignOn::Identity *m_identity = nullptr;
    SignOn::AuthSession *m_authSession = nullptr;
    bool m_credentialsReady = false;
};

class ProtonCalendarPlugin : public Buteo::ClientPlugin
{
    Q_OBJECT
public:
    ProtonCalendarPlugin(const QString &aPluginName,
                         const Buteo::SyncProfile &aProfile,
                         Buteo::PluginCbInterface *aCbInterface);
    ~ProtonCalendarPlugin() override;
    bool init() override;
    bool uninit() override;
    bool startSync() override;
    void abortSync(Sync::SyncStatus aStatus = Sync::SYNC_ABORTED) override;
    bool cleanUp() override;
    Buteo::SyncResults getSyncResults() const override;
public slots:
    void connectivityStateChanged(Sync::ConnectivityType aType, bool aState) override;
public:
    static QDateTime parseCalTime(const QString &ical, qint64 unixFallback, const QString &tz);
private slots:
    void pollCalendarStatus();
    void onCalendarSignOnResponse(const SignOn::SessionData &data);
    void onCalendarSignOnError(const SignOn::Error &error);
private:
    bool requestCalendarCredentials();
    bool writeEventsToMkCal(const QByteArray &json);
    QString findOrCreateNotebook(mKCal::ExtendedCalendar::Ptr cal,
                                 mKCal::ExtendedStorage::Ptr storage,
                                 const QString &calId,
                                 const QString &calName);
    QString namespacedUid(const QString &calId, const QString &raw, qint64 recurrenceId = 0) const;
    void persistCalendarTokens(const QString &refreshToken, const QString &uid);
    QPair<QString, QString> loadPersistedCalendarTokens();
    void persistCalendarDefaults(const QString &defaultsJson);
    QString loadCalendarDefaults();
    void persistUpsyncAnchors(const QString &anchorsJson);
    QString loadUpsyncAnchors();
    // Posted-but-unconfirmed creates ({mKCal UID: stable event UID}) for
    // retry idempotency. Persisted wholesale on EVERY run outcome
    // (complete AND error); empty clears stale entries, never merges.
    void persistCalendarPending(const QString &pendingJson);
    void persistUpsyncMaps(const QJsonArray &events,
                           const mKCal::ExtendedCalendar::Ptr &cal);
    void purgeListedTombstones(const mKCal::ExtendedStorage::Ptr &storage,
                               const QStringList &notebookUids,
                               const QSet<QString> &uids);
    QJsonArray exportLocalInventory();

    ProtonCalendarEngine *m_calEngine = nullptr;
    QTimer *m_calTimer = nullptr;
    // Planner purgeable UIDs from the last `complete` run (unioned with
    // replacement-phase removals at purge time; cleared on uninit).
    QSet<QString> m_purgeableUids;
    QString m_accountId;
    Accounts::Manager *m_accountManager = nullptr;
    SignOn::Identity *m_identity = nullptr;
    SignOn::AuthSession *m_authSession = nullptr;
    bool m_credentialsReady = false;
    bool m_inited = false;
};

class ProtonPluginLoader : public Buteo::SyncPluginLoader
{
    Q_OBJECT
    Q_INTERFACES(Buteo::SyncPluginLoader)
    Q_PLUGIN_METADATA(IID "com.buteo.msyncd.SyncPluginLoader/1.0")

public:
    Buteo::ClientPlugin *createClientPlugin(const QString &aPluginName,
                                            const Buteo::SyncProfile &aProfile,
                                            Buteo::PluginCbInterface *aCbInterface) override;
};

}
