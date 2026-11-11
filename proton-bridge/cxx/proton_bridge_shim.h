#pragma once

// Buteo client plugin for Proton Contacts and Calendar.
//
// An I/O adapter around the Rust sync session (proton_sync_step): it reads
// credentials (SignOn) and settings, dumps the phone's contacts / calendar
// events as raw JSON, executes the write plans it gets back and shows
// notifications. Every sync decision is made in Rust
// (proton-sync/src/device).

#include "ClientPlugin.h"
#include "SyncPluginLoader.h"

#include <QContactManager>
#include <QContact>
#include <QContactCollection>
#include <QContactCollectionId>
#include <QJsonArray>
#include <QJsonObject>
#include <QTimer>

#include <extendedcalendar.h>
#include <extendedstorage.h>
#include <KCalendarCore/Event>

#include <Accounts/manager.h>
#include <SignOn/identity.h>
#include <SignOn/authsession.h>
#include <SignOn/sessiondata.h>
#include <SignOn/signonerror.h>

#include "proton_bridge.h"

namespace Proton {

class ProtonSyncPlugin : public Buteo::ClientPlugin
{
    Q_OBJECT

public:
    ProtonSyncPlugin(const QString &aPluginName,
                     const Buteo::SyncProfile &aProfile,
                     Buteo::PluginCbInterface *aCbInterface,
                     bool calendar);
    ~ProtonSyncPlugin() override;

    bool init() override;
    bool uninit() override;
    bool startSync() override;
    void abortSync(Sync::SyncStatus aStatus = Sync::SYNC_ABORTED) override;
    bool cleanUp() override;
    Buteo::SyncResults getSyncResults() const override;

public slots:
    void connectivityStateChanged(Sync::ConnectivityType aType, bool aState) override;

private slots:
    void onSignOnResponse(const SignOn::SessionData &data);
    void onSignOnError(const SignOn::Error &error);
    void poll();

private:
    bool requestCredentials();
    // Feed one input to the Rust session and execute its requests until it
    // waits (poll) or finishes.
    void drive(QJsonObject input);
    void finish(const QJsonObject &result);

    // Contacts store (QtContacts, our per-account collection).
    QJsonObject dumpContacts();
    QJsonObject writeContacts(const QJsonObject &plan);
    QtContacts::QContactCollection findOrCreateCollection();

    // Calendar store (mKCal, our per-calendar notebooks).
    QJsonObject dumpCalendar();
    QJsonObject writeCalendar(const QJsonObject &plan);
    bool ensureNotebook(const QString &uid, const QString &name);

    const bool m_calendar;
    QString m_accountId;
    ProtonSync *m_sync = nullptr;
    QTimer m_timer;

    Accounts::Manager *m_accountManager = nullptr;
    SignOn::Identity *m_identity = nullptr;
    SignOn::AuthSession *m_authSession = nullptr;

    // Store handles kept from a dump to the write plan that refers to it
    // by index.
    QtContacts::QContactManager *m_contacts = nullptr;
    QtContacts::QContactCollectionId m_collectionId;
    QList<QtContacts::QContact> m_dumpedContacts;
    mKCal::ExtendedCalendar::Ptr m_cal;
    mKCal::ExtendedStorage::Ptr m_storage;
    KCalendarCore::Event::List m_dumpedEvents;
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
