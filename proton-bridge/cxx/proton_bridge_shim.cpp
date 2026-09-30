#include "proton_bridge_shim.h"
#include "proton_log.h"
#include <QBuffer>
#include <QDebug>
#include <QThread>
#include <QFile>
#include <QDateTime>
#include <QImage>
#include <QRegularExpression>
#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QUrl>

// Verbose gate (2026-09-09): routine content-heavy lines only log when
// PROTON_VERBOSE is set (non-empty, not "0") — same rule as Rust
// `proton_api::diag::verbose()`. The oopp-runner inherits msyncd's
// environment, so flip without root via:
//   systemctl --user set-environment PROTON_VERBOSE=1 && systemctl --user restart msyncd
// Errors, one-line summaries and IDs-only traces always log.
static bool proton_verbose() {
    const QByteArray v = qgetenv("PROTON_VERBOSE");
    return !v.isEmpty() && v != "0";
}

static void proton_log_verbose(const QString &msg) {
    if (proton_verbose()) {
        proton_log(msg);
    }
}

// Merges DerivedPasswords maps from every known source into one JSON object.
// Different logins stored single-key maps in different QSettings groups
// ([accountId]={addr}, [Uid]={user}); first-hit-wins shadowed one key and
// broke whichever engine needed it (verified live 2026-09-06). Union is
// safe: every entry was verified by trial-unlock at login time.
// Priority on conflict (later overwrites): accountId < username < Uid < blob.
static void mergeDerivedMap(QVariantMap &into, const QString &json, const QString &src,
                            QStringList &used) {
    if (json.isEmpty()) {
        return;
    }
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        return;
    }
    const QVariantMap map = doc.toVariant().toMap();
    if (map.isEmpty()) {
        return;
    }
    for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
        into.insert(it.key(), it.value());
    }
    used << QStringLiteral("%1(%2)").arg(src).arg(map.size());
}

static QString loadMergedDerivedPasswords(const QString &accountId, const QString &uid,
                                          const QString &username, const QString &blobJson) {
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    QVariantMap merged;
    QStringList used;
    settings.beginGroup(accountId);
    mergeDerivedMap(merged, settings.value(QStringLiteral("derived_passwords")).toString(),
                    QStringLiteral("accountId"), used);
    settings.endGroup();
    if (!username.isEmpty()) {
        settings.beginGroup(username);
        mergeDerivedMap(merged, settings.value(QStringLiteral("derived_passwords")).toString(),
                        QStringLiteral("username"), used);
        settings.endGroup();
    }
    if (!uid.isEmpty()) {
        settings.beginGroup(uid);
        mergeDerivedMap(merged, settings.value(QStringLiteral("derived_passwords")).toString(),
                        QStringLiteral("Uid"), used);
        settings.endGroup();
    }
    mergeDerivedMap(merged, blobJson, QStringLiteral("blob"), used);
    if (merged.isEmpty()) {
        return QString();
    }
    proton_log(QStringLiteral("Merged DerivedPasswords from ") + used.join(QStringLiteral("+")));
    return QString::fromUtf8(QJsonDocument::fromVariant(merged).toJson(QJsonDocument::Compact));
}

static void sendProtonNotification(const QString &summary, const QString &body) {
    QDBusMessage msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.freedesktop.Notifications"),
        QStringLiteral("/org/freedesktop/Notifications"),
        QStringLiteral("org.freedesktop.Notifications"),
        QStringLiteral("Notify"));
    QVariantList args;
    args << QStringLiteral("proton-contacts") // app_name
         << (uint)0 // replaces_id
         << QStringLiteral("image://theme/icon-m-file-vcard") // app_icon
         << summary
         << body
         << QStringList() // actions
         << QVariantMap() // hints
         << (int)10000; // timeout
    msg.setArguments(args);
    QDBusConnection::sessionBus().call(msg, QDBus::NoBlock);
    proton_log(QStringLiteral("Notification: ") + summary + " – " + body);
}

using namespace Proton;

static const QString PROTON_SERVICE_NAME = QStringLiteral("proton-carddav");

ProtonContactsPlugin::ProtonContactsPlugin(const QString &aPluginName,
                                           const Buteo::SyncProfile &aProfile,
                                           Buteo::PluginCbInterface *aCbInterface)
    : Buteo::ClientPlugin(aPluginName, aProfile, aCbInterface)
    , m_manager(new QtContacts::QContactManager(QStringLiteral("org.nemomobile.contacts.sqlite")))
{
    proton_log(QStringLiteral("ProtonContactsPlugin constructed: ") + aPluginName
             + " profileName=" + getProfileName());
}

ProtonContactsPlugin::~ProtonContactsPlugin()
{
    if (m_engine) {
        proton_bridge_destroy_engine(m_engine);
        m_engine = nullptr;
    }
    delete m_manager;
}

bool ProtonContactsPlugin::init()
{
    proton_log(QStringLiteral("ProtonContactsPlugin::init() profileName=") + getProfileName());

    m_accountId = iProfile.key(QStringLiteral("accountid"));
    proton_log(QStringLiteral("accountid from profile: ") + (m_accountId.isEmpty() ? QStringLiteral("(empty)") : m_accountId));

    if (m_accountId.isEmpty()) {
        QString profileName = getProfileName();
        QRegularExpression re("-(\\d+)$");
        QRegularExpressionMatch match = re.match(profileName);
        if (match.hasMatch()) {
            m_accountId = match.captured(1);
            proton_log(QStringLiteral("Extracted accountid from profile name: ") + m_accountId);
        }
    }

    if (m_accountId.isEmpty()) {
        m_accountId = iProfile.key(QStringLiteral("account_id"));
        proton_log(QStringLiteral("Trying account_id: ") + (m_accountId.isEmpty() ? QStringLiteral("(empty)") : m_accountId));
    }

    if (m_accountId.isEmpty()) {
        proton_log(QStringLiteral("ERROR: Cannot determine accountid"));
        return false;
    }

    proton_log(QStringLiteral("accountid = ") + m_accountId);

    m_accountManager = new Accounts::Manager(this);
    if (!m_accountManager) {
        proton_log(QStringLiteral("ERROR: Failed to create Accounts::Manager"));
        return false;
    }

    return requestCredentials();
}

bool ProtonContactsPlugin::requestCredentials()
{
    Accounts::AccountId accId = static_cast<Accounts::AccountId>(m_accountId.toUInt());
    proton_log(QStringLiteral("Loading account id=") + QString::number(accId));

    Accounts::Account *account = Accounts::Account::fromId(m_accountManager, accId, this);
    if (!account) {
        proton_log(QStringLiteral("ERROR: Unable to load account ") + m_accountId);
        return false;
    }

    proton_log(QStringLiteral("Account loaded, provider=") + account->providerName());

    Accounts::Service service = m_accountManager->service(PROTON_SERVICE_NAME);
    if (!service.isValid()) {
        proton_log(QStringLiteral("ERROR: Unable to find service ") + PROTON_SERVICE_NAME);
        return false;
    }

    proton_log(QStringLiteral("Service found: ") + service.name());

    account->selectService(service);
    Accounts::AccountService *accountService = new Accounts::AccountService(account, service, this);
    Accounts::AuthData authData = accountService->authData();

    quint32 credentialsId = authData.credentialsId();
    if (credentialsId == 0) {
        // Some creation flows store CredentialsId as int32, which the
        // authData() uint32 getter cannot read. Fall back to the generic
        // settings read (which converts) and heal the stored type.
        account->selectService(service);
        QVariant raw = account->value(QStringLiteral("CredentialsId"));
        if (raw.isValid() && raw.toUInt() > 0) {
            credentialsId = raw.toUInt();
            proton_log(QStringLiteral("Healing CredentialsId (wrong variant type) to ") + QString::number(credentialsId));
            account->setCredentialsId(credentialsId);
            account->sync();
        }
    }
    if (credentialsId == 0) {
        // Last resort: the provider-wide default credentials.
        account->selectService(Accounts::Service());
        credentialsId = account->credentialsId();
        if (credentialsId > 0) {
            proton_log(QStringLiteral("Using account default credentials id ") + QString::number(credentialsId));
            account->selectService(service);
        }
    }

    proton_log(QStringLiteral("credentialsId=") + QString::number(credentialsId)
             + " method=" + authData.method() + " mechanism=" + authData.mechanism());

    m_identity = SignOn::Identity::existingIdentity(credentialsId, this);
    if (!m_identity) {
        proton_log(QStringLiteral("ERROR: Unable to create SignOn identity for id=") + QString::number(credentialsId));
        return false;
    }

    m_authSession = m_identity->createSession(authData.method());
    if (!m_authSession) {
        proton_log(QStringLiteral("ERROR: Unable to create SignOn auth session"));
        return false;
    }

    connect(m_authSession, &SignOn::AuthSession::response,
            this, &ProtonContactsPlugin::onSignOnResponse);
    connect(m_authSession, &SignOn::AuthSession::error,
            this, &ProtonContactsPlugin::onSignOnError);

    SignOn::SessionData sessionData;
    // The sync plugin must never trigger interactive prompts: tokens were
    // obtained during account creation / credentials update. If they have
    // expired beyond refresh, the sync reports an authentication failure and
    // the user re-enters credentials through the account settings UI.
    sessionData.setUiPolicy(SignOn::NoUserInteractionPolicy);
    m_authSession->process(sessionData, authData.mechanism());

    proton_log(QStringLiteral("SignOn auth session started (method=%1)").arg(authData.method()));
    return true;
}

void ProtonContactsPlugin::onSignOnResponse(const SignOn::SessionData &data)
{
    proton_log(QStringLiteral("onSignOnResponse()"));

    // Detect locked 2FA session returned via custom TwoFARequired flag (QML OTP flow)
    // or missing scopes. The sync plugin runs with NoUserInteractionPolicy, so it
    // cannot prompt for OTP – the user must update credentials via Settings.
    bool twoFARequired = data.getProperty(QStringLiteral("TwoFARequired")).toBool();
    if (twoFARequired) {
        QString err = QStringLiteral("Two-factor authentication required – please update credentials in Settings → Proton and enter OTP code");
        proton_log(QStringLiteral("2FA required but no UI allowed in sync session"));
        emit error(getProfileName(), err, Buteo::SyncResults::AUTHENTICATION_FAILURE);
        return;
    }

    QString username = data.UserName();
    QString password = data.Secret();
    QString accessToken = data.getProperty(QStringLiteral("AccessToken")).toString();
    QString refreshToken = data.getProperty(QStringLiteral("RefreshToken")).toString();
    QString uid = data.getProperty(QStringLiteral("Uid")).toString();
    QString derivedJson = data.getProperty(QStringLiteral("DerivedPasswords")).toString();

    // Try Secret via Secret() and via getProperty for robustness (signond may strip Secret)
    QString secretViaProperty = data.getProperty(QStringLiteral("Secret")).toString();
    QString passwordViaProperty = data.getProperty(QStringLiteral("Password")).toString();
    QString userNameViaProperty = data.getProperty(QStringLiteral("UserName")).toString();
    if (password.isEmpty() && !secretViaProperty.isEmpty()) password = secretViaProperty;
    if (password.isEmpty() && !passwordViaProperty.isEmpty()) password = passwordViaProperty;
    if (username.isEmpty() && !userNameViaProperty.isEmpty()) username = userNameViaProperty;
    proton_log(QStringLiteral("Got credentials: username=") + username + " (viaProp=" + userNameViaProperty + ")"
             + " pw_len=" + QString::number(password.length()) + " (Secret prop len=" + QString::number(secretViaProperty.length()) + " Password prop len=" + QString::number(passwordViaProperty.length()) + ")"
             + " access_token=" + (accessToken.isEmpty() ? QStringLiteral("(none)") : QStringLiteral("(present)"))
             + " refresh_token=" + (refreshToken.isEmpty() ? QStringLiteral("(none)") : QStringLiteral("(present)"))
             + " uid=" + (uid.isEmpty() ? QStringLiteral("(none)") : uid)
             + " derived=" + (derivedJson.isEmpty() ? QStringLiteral("(none)") : QStringLiteral("(present)")) + " derived_len=" + QString::number(derivedJson.length())
             + " allKeys=" + data.propertyNames().join(","));

    if (refreshToken.isEmpty() || uid.isEmpty()) {
        auto tokens = loadPersistedTokens();
        if (refreshToken.isEmpty()) refreshToken = tokens.first;
        if (uid.isEmpty()) uid = tokens.second;
    }
    if (derivedJson.isEmpty()) {
        derivedJson = loadMergedDerivedPasswords(m_accountId, uid, username, QString());
    } else {
        proton_log(QStringLiteral("Using DerivedPasswords from SignOn blob"));
        // Still merge QSettings groups underneath: the blob is wiped to
        // tokens-only on every refresh, so it may hold fewer keys.
        QString merged = loadMergedDerivedPasswords(m_accountId, uid, username, derivedJson);
        if (!merged.isEmpty()) {
            derivedJson = merged;
        }
    }

    if (accessToken.isEmpty() && refreshToken.isEmpty()) {
        emit error(getProfileName(), QStringLiteral("No auth tokens received"), Buteo::SyncResults::AUTHENTICATION_FAILURE);
        return;
    }

    // If derived passwords are available, password can be empty (derived-only mode)
    // Keep password for first sync to generate derived, afterwards derived will be used
    // Upsync inputs: local inventory + known UIDs + anchors. Empty inventory
    // = download-only, identical to the old constructor path.
    QJsonArray contactsInventory = exportContactsInventory();
    QByteArray contactsInventoryJson =
        QJsonDocument(contactsInventory).toJson(QJsonDocument::Compact);
    QJsonArray knownUidsArr;
    for (const QString &knownUid : loadContactsKnownUids()) {
        knownUidsArr.append(knownUid);
    }
    QByteArray knownUidsJson =
        QJsonDocument(knownUidsArr).toJson(QJsonDocument::Compact);
    proton_log(QStringLiteral("Contacts inventory: %1 rows").arg(contactsInventory.size()));
    // Upsync trace inputs (2026-09-09 incident: upload decisions were only
    // on stderr/journal — log what the planner will see). Identity flags
    // only (never field contents, which the download path already logs):
    // proton_uid=null rows plan creates, known-but-absent UIDs plan deletes.
    {
        QJsonArray flags;
        for (const QJsonValue &v : contactsInventory) {
            QJsonObject o = v.toObject();
            QJsonObject f;
            f.insert(QStringLiteral("qid"), o.value(QLatin1String("qcontact_id")).toString());
            f.insert(QStringLiteral("uid"), o.value(QLatin1String("proton_uid")));
            f.insert(QStringLiteral("modified"), o.value(QLatin1String("modified")).toBool());
            f.insert(QStringLiteral("anchor"), o.value(QLatin1String("last_synced_mtime")));
            f.insert(QStringLiteral("has_fields"), o.contains(QLatin1String("fields")));
            flags.append(f);
        }
        proton_log(QStringLiteral("Contacts upsync in: %1")
                       .arg(QString::fromUtf8(QJsonDocument(flags).toJson(QJsonDocument::Compact)).left(3000)));
    }
    proton_log(QStringLiteral("Contacts upsync known=%1 anchors=%2")
                   .arg(QString::fromUtf8(knownUidsJson).left(2000))
                   .arg(loadContactsAnchors().left(500)));
    m_engine = proton_bridge_create_engine_with_inventory(
        username.toUtf8().constData(),
        password.toUtf8().constData(),
        accessToken.toUtf8().constData(),
        refreshToken.toUtf8().constData(),
        uid.toUtf8().constData(),
        "",
        derivedJson.toUtf8().constData(),
        contactsInventoryJson.constData(),
        knownUidsJson.constData(),
        loadContactsAnchors().toUtf8().constData());

    if (!m_engine) {
        emit error(getProfileName(), QStringLiteral("Failed to create sync engine"), Buteo::SyncResults::INTERNAL_ERROR);
        return;
    }

    m_credentialsReady = true;
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &ProtonContactsPlugin::pollStatus);
    if (!startSync()) {
        emit error(getProfileName(), QStringLiteral("Failed to start sync"), Buteo::SyncResults::INTERNAL_ERROR);
    }
}

void ProtonContactsPlugin::onSignOnError(const SignOn::Error &signOnError)
{
    proton_log(QStringLiteral("onSignOnError(): type=") + QString::number(signOnError.type())
             + " msg=" + signOnError.message());
    emit error(getProfileName(), QStringLiteral("Authentication failed: ") + signOnError.message(), Buteo::SyncResults::AUTHENTICATION_FAILURE);
}

bool ProtonContactsPlugin::uninit()
{
    proton_log(QStringLiteral("ProtonContactsPlugin::uninit()"));

    if (m_timer) {
        m_timer->stop();
        delete m_timer;
        m_timer = nullptr;
    }

    if (m_engine) {
        proton_bridge_destroy_engine(m_engine);
        m_engine = nullptr;
    }

    m_credentialsReady = false;
    return true;
}

bool ProtonContactsPlugin::startSync()
{
    proton_log(QStringLiteral("startSync() credentialsReady=") + (m_credentialsReady ? "true" : "false"));

    if (!m_credentialsReady) {
        qDebug() << "ProtonContactsPlugin: credentials not ready yet, will start sync after auth";
        return true;
    }

    if (!m_engine) {
        qWarning() << "Engine not initialized";
        emit error(getProfileName(), QStringLiteral("Engine not initialized"), Buteo::SyncResults::INTERNAL_ERROR);
        return false;
    }

    bool ok = proton_bridge_start_sync(m_engine);
    if (!ok) {
        qWarning() << "Failed to start sync";
        emit error(getProfileName(), QStringLiteral("Failed to start sync"), Buteo::SyncResults::INTERNAL_ERROR);
        return false;
    }

    m_timer->start(500);
    return true;
}

void ProtonContactsPlugin::abortSync(Sync::SyncStatus aStatus)
{
    Q_UNUSED(aStatus);
    qDebug() << "ProtonContactsPlugin::abortSync()";

    if (m_timer) {
        m_timer->stop();
    }

    if (m_engine) {
        proton_bridge_abort_sync(m_engine);
    }
}

bool ProtonContactsPlugin::cleanUp()
{
    qDebug() << "ProtonContactsPlugin::cleanUp()";
    return true;
}

Buteo::SyncResults ProtonContactsPlugin::getSyncResults() const
{
    return Buteo::SyncResults();
}

void ProtonContactsPlugin::connectivityStateChanged(Sync::ConnectivityType aType, bool aState)
{
    Q_UNUSED(aType);
    Q_UNUSED(aState);
}

void ProtonContactsPlugin::pollStatus()
{
    if (!m_engine) {
        return;
    }

    ProtonBridgeStatus status;
    proton_bridge_get_status(m_engine, &status);

    QString state = QString::fromUtf8(reinterpret_cast<const char*>(status.state),
                                      strnlen(reinterpret_cast<const char*>(status.state), 16));

    qDebug() << "Sync status:" << state << "progress:" << status.progress
             << "contacts:" << status.synced_contacts << "/" << status.total_contacts;

    if (state == QLatin1String("complete")) {
        m_timer->stop();

        char *rt = proton_bridge_get_refresh_token(m_engine);
        char *uid = proton_bridge_get_uid(m_engine);
        if (rt && uid) {
            persistTokens(QString::fromUtf8(rt), QString::fromUtf8(uid));
        }
        if (rt) proton_bridge_free_string(rt);
        if (uid) proton_bridge_free_string(uid);

        // Persist derived mailbox passwords (encrypted via SignOn on next auth, plus QSettings cache)
        char *derived = proton_bridge_get_derived_passwords_json(m_engine);
        if (derived) {
            QString derivedJson = QString::fromUtf8(derived);
            proton_bridge_free_string(derived);
            if (!derivedJson.isEmpty() && derivedJson != QStringLiteral("null")) {
                QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
                settings.beginGroup(m_accountId);
                settings.setValue(QStringLiteral("derived_passwords"), derivedJson);
                settings.endGroup();
                proton_log(QStringLiteral("Persisted derived passwords for account ") + m_accountId);
                // Also update SignOn identity with derived passwords (encrypted storage)
                if (m_identity) {
                    SignOn::IdentityInfo info;
                    // Query current info async – for now store via QSettings cache is used as derived source
                    // Future: store via SignOn custom property "DerivedPasswords"
                }
            }
        }

        char *keysDbg = proton_bridge_get_keys_debug(m_engine);
        QString keysDebug = keysDbg ? QString::fromUtf8(keysDbg) : QString();
        if (keysDbg) proton_bridge_free_string(keysDbg);
        proton_log(QStringLiteral("Keys debug: ") + keysDebug);

        // Upsync outputs (only meaningful on `complete`, which is where we
        // are): anchors persist wholesale (null/empty never clobbers),
        // conflicts notify server-wins, pending persists wholesale too
        // (empty clears — a confirmed cycle must drop stale retry UIDs).
        char *contactAnchors = proton_bridge_get_contact_anchors_json(m_engine);
        if (contactAnchors) {
            persistContactsAnchors(QString::fromUtf8(contactAnchors));
            proton_bridge_free_string(contactAnchors);
        }
        char *contactPending = proton_bridge_get_contact_pending_json(m_engine);
        persistContactsPending(contactPending ? QString::fromUtf8(contactPending) : QString());
        if (contactPending) proton_bridge_free_string(contactPending);
        char *contactConflicts = proton_bridge_get_contact_conflicts_json(m_engine);
        QStringList noticeParts;
        if (contactConflicts) {
            QJsonDocument doc = QJsonDocument::fromJson(QByteArray(contactConflicts));
            proton_bridge_free_string(contactConflicts);
            if (doc.isArray() && !doc.array().isEmpty()) {
                noticeParts << QStringLiteral("%1 contacts changed on both sides; server version kept").arg(doc.array().size());
            }
        }
        // Skipped uploads (IDs + reason codes only, never contents): the
        // download overwrote them, so the user hears about it here. The
        // full list lands in the file log for diagnosis.
        char *contactDeferred = proton_bridge_get_contact_deferred_json(m_engine);
        if (contactDeferred) {
            QJsonDocument doc = QJsonDocument::fromJson(QByteArray(contactDeferred));
            proton_bridge_free_string(contactDeferred);
            if (doc.isArray() && !doc.array().isEmpty()) {
                proton_log(QStringLiteral("Contacts deferred uploads: %1").arg(QString::fromUtf8(QJsonDocument(doc).toJson(QJsonDocument::Compact)).left(2000)));
                noticeParts << QStringLiteral("%1 local changes could not be uploaded; server version kept").arg(doc.array().size());
            }
        }
        if (!noticeParts.isEmpty()) {
            sendProtonNotification(
                QStringLiteral("Proton Contacts sync conflicts"),
                noticeParts.join(QStringLiteral("; ")));
        }

        char *json = proton_bridge_get_synced_contacts_json(m_engine);
        if (json) {
            QByteArray jsonData(json);
            proton_bridge_free_string(json);

            bool ok = writeContactsToQtPIM(jsonData);
            if (ok) {
                emit success(getProfileName(), QStringLiteral("Sync completed"));
            } else {
                emit error(getProfileName(), QStringLiteral("Failed to write contacts"), Buteo::SyncResults::INTERNAL_ERROR);
                sendProtonNotification(QStringLiteral("Proton Contacts sync failed"), QStringLiteral("Failed to write contacts to phone"));
            }
        } else {
            emit success(getProfileName(), QStringLiteral("Sync completed (no contacts)"));
        }
    } else if (state == QLatin1String("error")) {
        m_timer->stop();
        QString errMsg = QString::fromUtf8(reinterpret_cast<const char*>(status.error),
                                           strnlen(reinterpret_cast<const char*>(status.error), 256));
        proton_log(QStringLiteral("Sync error: ") + errMsg);
        char *keysDbg = proton_bridge_get_keys_debug(m_engine);
        QString keysDebug = keysDbg ? QString::fromUtf8(keysDbg) : QString();
        if (keysDbg) proton_bridge_free_string(keysDbg);
        proton_log(QStringLiteral("Keys debug on error: ") + keysDebug);
        // The error path is exactly when posted-but-unconfirmed creates
        // exist (e.g. re-list failed after successful POSTs): persist the
        // pending retry UIDs wholesale so the next cycle reuses them.
        char *contactPending = proton_bridge_get_contact_pending_json(m_engine);
        persistContactsPending(contactPending ? QString::fromUtf8(contactPending) : QString());
        if (contactPending) proton_bridge_free_string(contactPending);
        // Emit authentication failure so Settings shows “Account not signed in” and user can re-enter credentials
        auto code = Buteo::SyncResults::AUTHENTICATION_FAILURE;
        sendProtonNotification(QStringLiteral("Proton Contacts sync failed"), errMsg);
        emit error(getProfileName(), errMsg, code);
    } else if (state == QLatin1String("needs_2fa")) {
        // Distinct from generic auth failure: the account needs a fresh OTP
        // code (Settings → Proton → Update credentials). Without this branch
        // the poll timer would spin forever on a non-terminal state.
        m_timer->stop();
        QString errMsg = QString::fromUtf8(reinterpret_cast<const char*>(status.error),
                                           strnlen(reinterpret_cast<const char*>(status.error), 256));
        if (errMsg.isEmpty()) {
            errMsg = QStringLiteral("Two-factor authentication required");
        }
        proton_log(QStringLiteral("Sync needs 2FA: ") + errMsg);
        sendProtonNotification(QStringLiteral("Proton Contacts needs verification"),
                               errMsg + QStringLiteral(" – open Settings → Accounts → Proton, update credentials and enter your one-time code"));
        emit error(getProfileName(), errMsg, Buteo::SyncResults::AUTHENTICATION_FAILURE);
    }
}

bool ProtonContactsPlugin::writeContactsToQtPIM(const QByteArray &json)
{
    QJsonDocument doc = QJsonDocument::fromJson(json);
    if (!doc.isArray()) {
        proton_log(QStringLiteral("Expected JSON array of contacts"));
        return false;
    }

    QtContacts::QContactCollection collection = findOrCreateCollection();
    if (collection.id().isNull()) {
        proton_log(QStringLiteral("ERROR: Failed to create/find Proton contacts collection"));
        return false;
    }
    proton_log(QStringLiteral("Using collection id=") + collection.id().toString());

    QtContacts::QContactCollectionFilter collectionFilter;
    collectionFilter.setCollectionId(collection.id());
    QList<QtContacts::QContact> oldContacts = m_manager->contacts(collectionFilter);
    if (!oldContacts.isEmpty()) {
        QList<QtContacts::QContactId> oldIds;
        for (const auto &c : oldContacts) {
            oldIds.append(c.id());
        }
        QMap<int, QtContacts::QContactManager::Error> errorMap;
        m_manager->removeContacts(oldIds, &errorMap);
        proton_log(QStringLiteral("Removed %1 old contacts from Proton collection").arg(oldIds.size()));
    }

    QJsonArray contacts = doc.array();
    QList<QtContacts::QContact> qtContacts;

    for (const QJsonValue &val : contacts) {
        QJsonObject obj = val.toObject();
        // Full row JSON (names, addresses, photo data-URIs): verbose-only.
        // The one-line "Saved N contacts" + keys_debug summary always log.
        proton_log_verbose(QStringLiteral("Contact JSON: ") + QJsonDocument(obj).toJson(QJsonDocument::Compact).left(2000));

        QtContacts::QContact contact;
        contact.setCollectionId(collection.id());

        QtContacts::QContactSyncTarget st;
        st.setSyncTarget(QStringLiteral("proton"));
        contact.saveDetail(&st);

        QString firstName = obj.value(QLatin1String("first_name")).toString();
        QString lastName = obj.value(QLatin1String("last_name")).toString();
        QString displayName = obj.value(QLatin1String("display_name")).toString();

        if (firstName.isEmpty() && lastName.isEmpty() && !displayName.isEmpty()) {
            QStringList parts = displayName.split(QLatin1Char(' '));
            if (parts.size() >= 2) {
                firstName = parts.mid(0, parts.size() - 1).join(QLatin1Char(' '));
                lastName = parts.last();
            } else {
                firstName = displayName;
            }
        }

        if (!firstName.isEmpty() || !lastName.isEmpty()) {
            QtContacts::QContactName nameDetail;
            nameDetail.setFirstName(firstName);
            nameDetail.setLastName(lastName);
            contact.saveDetail(&nameDetail);
        }

        if (!displayName.isEmpty()) {
            QtContacts::QContactDisplayLabel labelDetail;
            labelDetail.setLabel(displayName);
            contact.saveDetail(&labelDetail);
        }

        QString contactUid = obj.value(QLatin1String("uid")).toString();
        if (!contactUid.isEmpty()) {
            QtContacts::QContactGuid guidDetail;
            guidDetail.setGuid(contactUid);
            contact.saveDetail(&guidDetail);
        }

        QJsonArray emails = obj.value(QLatin1String("emails")).toArray();
        for (const QJsonValue &ev : emails) {
            QJsonObject eo = ev.toObject();
            QString email = eo.value(QLatin1String("email")).toString();
            if (email.isEmpty()) continue;
            QtContacts::QContactEmailAddress emailDetail;
            emailDetail.setEmailAddress(email);
            QList<int> contexts;
            QJsonArray emailTypes = eo.value(QLatin1String("types")).toArray();
            for (const QJsonValue &tv : emailTypes) {
                QString typeStr = tv.toString().toLower();
                if (typeStr == QLatin1String("home"))
                    contexts << QtContacts::QContactDetail::ContextHome;
                else if (typeStr == QLatin1String("work"))
                    contexts << QtContacts::QContactDetail::ContextWork;
            }
            if (!contexts.isEmpty()) emailDetail.setContexts(contexts);
            contact.saveDetail(&emailDetail);
        }

        QJsonArray phones = obj.value(QLatin1String("phones")).toArray();
        for (const QJsonValue &pv : phones) {
            QJsonObject po = pv.toObject();
            QString number = po.value(QLatin1String("number")).toString();
            if (number.isEmpty()) continue;
            QtContacts::QContactPhoneNumber phoneDetail;
            phoneDetail.setNumber(number);
            QList<int> subTypes;
            QList<int> contexts;
            QJsonArray phoneTypes = po.value(QLatin1String("types")).toArray();
            for (const QJsonValue &tv : phoneTypes) {
                QString typeStr = tv.toString().toLower();
                if (typeStr == QLatin1String("cell") || typeStr == QLatin1String("mobile"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypeMobile;
                else if (typeStr == QLatin1String("fax"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypeFax;
                else if (typeStr == QLatin1String("pager"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypePager;
                else if (typeStr == QLatin1String("voice"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypeVoice;
                else if (typeStr == QLatin1String("video"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypeVideo;
                else if (typeStr == QLatin1String("car"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypeCar;
                else if (typeStr == QLatin1String("home"))
                    contexts << QtContacts::QContactDetail::ContextHome;
                else if (typeStr == QLatin1String("work"))
                    contexts << QtContacts::QContactDetail::ContextWork;
            }
            if (!subTypes.isEmpty()) phoneDetail.setSubTypes(subTypes);
            if (!contexts.isEmpty()) phoneDetail.setContexts(contexts);
            contact.saveDetail(&phoneDetail);
        }

        QJsonArray addresses = obj.value(QLatin1String("addresses")).toArray();
        for (const QJsonValue &av : addresses) {
            QJsonObject ao = av.toObject();
            QtContacts::QContactAddress addrDetail;
            addrDetail.setStreet(ao.value(QLatin1String("street")).toString());
            addrDetail.setLocality(ao.value(QLatin1String("locality")).toString());
            addrDetail.setRegion(ao.value(QLatin1String("region")).toString());
            addrDetail.setPostcode(ao.value(QLatin1String("postal_code")).toString());
            addrDetail.setCountry(ao.value(QLatin1String("country")).toString());
            QList<int> contexts;
            QJsonArray addrTypes = ao.value(QLatin1String("types")).toArray();
            for (const QJsonValue &tv : addrTypes) {
                QString typeStr = tv.toString().toLower();
                if (typeStr == QLatin1String("home"))
                    contexts << QtContacts::QContactDetail::ContextHome;
                else if (typeStr == QLatin1String("work"))
                    contexts << QtContacts::QContactDetail::ContextWork;
            }
            if (!contexts.isEmpty()) addrDetail.setContexts(contexts);
            contact.saveDetail(&addrDetail);
        }

        QString org = obj.value(QLatin1String("organization")).toString();
        QString title = obj.value(QLatin1String("title")).toString();
        QString role = obj.value(QLatin1String("role")).toString();
        if (!org.isEmpty() || !title.isEmpty() || !role.isEmpty()) {
            QtContacts::QContactOrganization orgDetail;
            if (!org.isEmpty()) orgDetail.setName(org);
            if (!title.isEmpty()) orgDetail.setTitle(title);
            if (!role.isEmpty()) orgDetail.setRole(role);
            contact.saveDetail(&orgDetail);
        }

        QJsonArray notesArr = obj.value(QLatin1String("notes")).toArray();
        if (!notesArr.isEmpty()) {
            QStringList noteParts;
            for (const QJsonValue &nv : notesArr) {
                QString n = nv.toString();
                if (!n.isEmpty()) noteParts << n;
            }
            if (!noteParts.isEmpty()) {
                QtContacts::QContactNote noteDetail;
                noteDetail.setNote(noteParts.join(QLatin1String("\n")));
                contact.saveDetail(&noteDetail);
            }
        }

        QString birthday = obj.value(QLatin1String("birthday")).toString();
        if (!birthday.isEmpty()) {
            QtContacts::QContactBirthday bdayDetail;
            QDate bdayDate = QDate::fromString(birthday, Qt::ISODate);
            if (!bdayDate.isValid()) {
                bdayDate = QDate::fromString(birthday, QStringLiteral("yyyyMMdd"));
            }
            if (bdayDate.isValid()) {
                bdayDetail.setDate(bdayDate);
                contact.saveDetail(&bdayDetail);
            }
        }

        QString anniversary = obj.value(QLatin1String("anniversary")).toString();
        if (!anniversary.isEmpty()) {
            QtContacts::QContactAnniversary annDetail;
            QDate annDate = QDate::fromString(anniversary, Qt::ISODate);
            if (!annDate.isValid()) {
                annDate = QDate::fromString(anniversary, QStringLiteral("yyyyMMdd"));
            }
            if (annDate.isValid()) {
                annDetail.setOriginalDate(annDate);
                contact.saveDetail(&annDetail);
            }
        }

        QString nickname = obj.value(QLatin1String("nickname")).toString();
        if (!nickname.isEmpty()) {
            QtContacts::QContactNickname nickDetail;
            nickDetail.setNickname(nickname);
            contact.saveDetail(&nickDetail);
        }

        QString url = obj.value(QLatin1String("url")).toString();
        if (!url.isEmpty()) {
            QtContacts::QContactUrl urlDetail;
            urlDetail.setUrl(url);
            contact.saveDetail(&urlDetail);
        }

        QString gender = obj.value(QLatin1String("gender")).toString();
        if (!gender.isEmpty()) {
            QtContacts::QContactGender genderDetail;
            if (gender.compare(QLatin1String("Male"), Qt::CaseInsensitive) == 0) {
                genderDetail.setGender(QtContacts::QContactGender::GenderMale);
            } else if (gender.compare(QLatin1String("Female"), Qt::CaseInsensitive) == 0) {
                genderDetail.setGender(QtContacts::QContactGender::GenderFemale);
            } else {
                genderDetail.setGender(QtContacts::QContactGender::GenderMale);
            }
            contact.saveDetail(&genderDetail);
        }

        QJsonArray photosArr = obj.value(QLatin1String("photos")).toArray();
        if (!photosArr.isEmpty()) {
            QString photoUrl = photosArr.first().toString();
            if (!photoUrl.isEmpty()) {
                QtContacts::QContactAvatar avatarDetail;
                if (photoUrl.startsWith(QLatin1String("data:"))) {
                    avatarDetail.setImageUrl(QUrl(photoUrl));
                } else {
                    avatarDetail.setImageUrl(QUrl::fromEncoded(photoUrl.toUtf8()));
                }
                contact.saveDetail(&avatarDetail);
            }
        }

        qtContacts.append(contact);
    }

    if (!qtContacts.isEmpty()) {
        QMap<int, QtContacts::QContactManager::Error> errorMap;
        if (!m_manager->saveContacts(&qtContacts, &errorMap)) {
            proton_log(QStringLiteral("Failed to save contacts, error=") + QString::number(static_cast<int>(m_manager->error())));
            for (auto it = errorMap.constBegin(); it != errorMap.constEnd(); ++it) {
                proton_log(QStringLiteral("Save error index=%1 code=%2").arg(it.key()).arg(it.value()));
            }
            return false;
        }
        QCoreApplication::processEvents();
        proton_log(QStringLiteral("Saved %1 contacts via QContactManager, error=%2").arg(qtContacts.size()).arg(static_cast<int>(m_manager->error())));
        // Upsync bookkeeping (write-only until the engine consumes it):
        // ID map + lastModified snapshots for change detection.
        persistContactsMaps(qtContacts);
    }

    return true;
}

// Upsync bookkeeping for contacts (write-only until the engine consumes
// it; mirrors the calendar proton_id_map/anchors pattern, minus tombstones
// — QtContacts has no delete tracking, so deletes come from ID-map diffing
// instead). Three JSON blobs under QSettings proton/sync-tokens/<account>:
// - contacts_id_map: {proton_uid: qcontact_id string} — known set for delete
//   detection + Guid fallback ( Guid is authoritative; the map is the net).
// - contacts_last_modified: {qcontact_id: lastModified msecs} — dirt baseline
//   (missing entry = treat clean, so pre-feature rows never mass-upload).
// - contacts_anchors: {proton_uid: server ModifyTime} — planner anchors,
//   persisted wholesale from the engine getter (never clobbered with empty).
static QStringList contactContextsToTypes(const QList<int> &contexts) {
    QStringList out;
    if (contexts.contains(QtContacts::QContactDetail::ContextHome)) {
        out << QStringLiteral("home");
    }
    if (contexts.contains(QtContacts::QContactDetail::ContextWork)) {
        out << QStringLiteral("work");
    }
    return out;
}

static QStringList contactPhoneSubTypesToTypes(const QList<int> &subTypes) {
    QStringList out;
    typedef QtContacts::QContactPhoneNumber P;
    if (subTypes.contains(P::SubTypeMobile)) out << QStringLiteral("cell");
    if (subTypes.contains(P::SubTypeFax)) out << QStringLiteral("fax");
    if (subTypes.contains(P::SubTypePager)) out << QStringLiteral("pager");
    if (subTypes.contains(P::SubTypeVoice)) out << QStringLiteral("voice");
    if (subTypes.contains(P::SubTypeVideo)) out << QStringLiteral("video");
    if (subTypes.contains(P::SubTypeCar)) out << QStringLiteral("car");
    return out;
}

void ProtonContactsPlugin::persistContactsMaps(const QList<QtContacts::QContact> &saved) {
    // Assigned IDs are valid on the in-memory objects post-save; timestamps
    // and avatars are re-fetched per row (the in-memory copies may predate
    // storage — and the avatar string must be the STORED form so the export
    // comparison below is like-for-like through QUrl).
    QVariantMap idMap, lastMod, photos;
    for (const QtContacts::QContact &c : saved) {
        if (c.id().isNull()) continue;
        QString uid = c.detail<QtContacts::QContactGuid>().guid();
        if (uid.isEmpty()) continue;
        QString qid = c.id().toString();
        idMap.insert(uid, qid);
        QtContacts::QContact fresh = m_manager->contact(c.id());
        if (m_manager->error() != QtContacts::QContactManager::NoError) continue;
        QtContacts::QContactTimestamp ts = fresh.detail<QtContacts::QContactTimestamp>();
        if (ts.lastModified().isValid()) {
            lastMod.insert(qid, ts.lastModified().toMSecsSinceEpoch());
        }
        const QList<QtContacts::QContactAvatar> avatars =
            fresh.details<QtContacts::QContactAvatar>();
        // Last detail wins (see export): app edits accumulate stale ones.
        if (!avatars.isEmpty()) {
            const QString avatarStr = avatars.last().imageUrl().toString();
            if (!avatarStr.isEmpty()) {
                photos.insert(qid, avatarStr);
            }
        }
    }
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    settings.setValue(QStringLiteral("contacts_id_map"),
                      QString::fromUtf8(QJsonDocument::fromVariant(idMap).toJson(QJsonDocument::Compact)));
    settings.setValue(QStringLiteral("contacts_last_modified"),
                      QString::fromUtf8(QJsonDocument::fromVariant(lastMod).toJson(QJsonDocument::Compact)));
    settings.setValue(QStringLiteral("contacts_photos"),
                      QString::fromUtf8(QJsonDocument::fromVariant(photos).toJson(QJsonDocument::Compact)));
    settings.endGroup();
}

// Avatar (device photo) → data URI for the vCard PHOTO line. `data:`
// URIs (download echoes) pass through; file paths (user-set avatars)
// load + downscale (WebClients imports cap at CONTACT_IMG_SIZE=180;
// 512px bounding + JPEG q85 here balances quality against card size).
// Returns "" when there is nothing usable — the caller then omits the
// photos key (serde default), keeping the server copy on update.
static QString avatarToDataUri(const QString &avatarStr) {
    if (avatarStr.isEmpty()) {
        return QString();
    }
    if (avatarStr.startsWith(QLatin1String("data:"))) {
        return avatarStr;
    }
    const QString localFile = QUrl(avatarStr).toLocalFile();
    const QString path = localFile.isEmpty() ? avatarStr : localFile;
    QImage image(path);
    if (image.isNull()) {
        return QString();
    }
    if (qMax(image.width(), image.height()) > 512) {
        image = image.scaled(512, 512, Qt::KeepAspectRatio, Qt::SmoothTransformation);
    }
    QByteArray bytes;
    QBuffer buffer(&bytes);
    if (!buffer.open(QIODevice::WriteOnly) || !image.save(&buffer, "JPEG", 85)) {
        return QString();
    }
    return QStringLiteral("data:image/jpeg;base64,") + QString::fromLatin1(bytes.toBase64());
}

// Local inventory for the contacts planner: one object per row in our
// collection — {qcontact_id, proton_uid|null, modified, last_synced_mtime
// |null, fields?} (exact `contact_plan::ContactItem` contract). `fields`
// carries the full phone snapshot for dirty/never-synced rows only,
// including `photos` (device avatar as data URI) when the avatar differs
// from the persisted download baseline — untouched avatars stay omitted
// so the server copy is carried engine-side (no re-upload churn, no
// QUrl round-trip risk on echoes).
QJsonArray ProtonContactsPlugin::exportContactsInventory() {
    QJsonArray out;
    QtContacts::QContactCollection collection = findOrCreateCollection();
    if (collection.id().isNull()) return out;
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    auto readMap = [&](const QString &key) {
        QVariantMap map;
        QJsonDocument doc = QJsonDocument::fromJson(
            settings.value(key).toString().toUtf8());
        if (doc.isObject()) map = doc.toVariant().toMap();
        return map;
    };
    QVariantMap anchors = readMap(QStringLiteral("contacts_anchors"));
    QVariantMap lastMod = readMap(QStringLiteral("contacts_last_modified"));
    QVariantMap pending = readMap(QStringLiteral("contacts_pending"));
    QVariantMap photosBaseline = readMap(QStringLiteral("contacts_photos"));
    settings.endGroup();

    QtContacts::QContactCollectionFilter collectionFilter;
    collectionFilter.setCollectionId(collection.id());
    QList<QtContacts::QContact> rows = m_manager->contacts(collectionFilter);
    for (const QtContacts::QContact &c : rows) {
        QJsonObject o;
        QString qid = c.id().toString();
        o.insert(QStringLiteral("qcontact_id"), qid);
        QString guid = c.detail<QtContacts::QContactGuid>().guid();
        o.insert(QStringLiteral("proton_uid"),
                 guid.isEmpty() ? QJsonValue() : QJsonValue(guid));
        bool dirty = false;
        QDateTime lm = c.detail<QtContacts::QContactTimestamp>().lastModified();
        if (lm.isValid() && lastMod.contains(qid)) {
            dirty = lastMod.value(qid).toLongLong() != lm.toMSecsSinceEpoch();
        }
        o.insert(QStringLiteral("modified"), dirty);
        if (!guid.isEmpty() && anchors.contains(guid)) {
            o.insert(QStringLiteral("last_synced_mtime"),
                     QJsonValue(anchors.value(guid).toLongLong()));
        } else {
            o.insert(QStringLiteral("last_synced_mtime"), QJsonValue());
        }
        if (!guid.isEmpty() && !dirty) {
            out.append(o); // clean synced row: no fields needed
            continue;
        }
        // Never-synced row: carry the stable retry UID (if the previous
        // cycle posted but never confirmed) so the next POST reuses it.
        if (guid.isEmpty() && pending.contains(qid)) {
            o.insert(QStringLiteral("pending_uid"), pending.value(qid).toString());
        }
        // Dirty or never-synced: full snapshot (mirror of the write path).
        QJsonObject f;
        QtContacts::QContactName name = c.detail<QtContacts::QContactName>();
        f.insert(QStringLiteral("first_name"), name.firstName());
        f.insert(QStringLiteral("last_name"), name.lastName());
        f.insert(QStringLiteral("display_name"),
                 c.detail<QtContacts::QContactDisplayLabel>().label());
        QJsonArray emails;
        for (const QtContacts::QContactEmailAddress &e :
             c.details<QtContacts::QContactEmailAddress>()) {
            if (e.emailAddress().isEmpty()) continue;
            QJsonObject eo;
            eo.insert(QStringLiteral("email"), e.emailAddress());
            QJsonArray types;
            for (const QString &t : contactContextsToTypes(e.contexts())) types.append(t);
            eo.insert(QStringLiteral("types"), types);
            emails.append(eo);
        }
        f.insert(QStringLiteral("emails"), emails);
        QJsonArray phones;
        for (const QtContacts::QContactPhoneNumber &p :
             c.details<QtContacts::QContactPhoneNumber>()) {
            if (p.number().isEmpty()) continue;
            QJsonObject po;
            po.insert(QStringLiteral("number"), p.number());
            QJsonArray types;
            for (const QString &t : contactPhoneSubTypesToTypes(p.subTypes())) types.append(t);
            for (const QString &t : contactContextsToTypes(p.contexts())) types.append(t);
            po.insert(QStringLiteral("types"), types);
            phones.append(po);
        }
        f.insert(QStringLiteral("phones"), phones);
        QJsonArray addresses;
        for (const QtContacts::QContactAddress &a :
             c.details<QtContacts::QContactAddress>()) {
            QJsonObject ao;
            ao.insert(QStringLiteral("street"), a.street());
            ao.insert(QStringLiteral("locality"), a.locality());
            ao.insert(QStringLiteral("region"), a.region());
            ao.insert(QStringLiteral("postal_code"), a.postcode());
            ao.insert(QStringLiteral("country"), a.country());
            QJsonArray types;
            for (const QString &t : contactContextsToTypes(a.contexts())) types.append(t);
            ao.insert(QStringLiteral("types"), types);
            addresses.append(ao);
        }
        f.insert(QStringLiteral("addresses"), addresses);
        QtContacts::QContactOrganization org = c.detail<QtContacts::QContactOrganization>();
        f.insert(QStringLiteral("organization"), org.name());
        f.insert(QStringLiteral("title"), org.title());
        f.insert(QStringLiteral("role"), org.role());
        QStringList notes;
        for (const QtContacts::QContactNote &n : c.details<QtContacts::QContactNote>()) {
            if (!n.note().isEmpty()) notes << n.note();
        }
        QJsonArray notesArr;
        for (const QString &n : notes) notesArr.append(n);
        f.insert(QStringLiteral("notes"), notesArr);
        QtContacts::QContactBirthday bday = c.detail<QtContacts::QContactBirthday>();
        f.insert(QStringLiteral("birthday"),
                 bday.date().isValid() ? bday.date().toString(Qt::ISODate) : QString());
        QtContacts::QContactAnniversary ann = c.detail<QtContacts::QContactAnniversary>();
        QDate annDate = ann.originalDate();
        f.insert(QStringLiteral("anniversary"),
                 annDate.isValid() ? annDate.toString(Qt::ISODate) : QString());
        f.insert(QStringLiteral("nickname"), c.detail<QtContacts::QContactNickname>().nickname());
        f.insert(QStringLiteral("url"), c.detail<QtContacts::QContactUrl>().url());
        QtContacts::QContactGender::GenderType gender =
            c.detail<QtContacts::QContactGender>().gender();
        QString genderStr;
        if (gender == QtContacts::QContactGender::GenderMale) {
            genderStr = QStringLiteral("Male");
        } else if (gender == QtContacts::QContactGender::GenderFemale) {
            genderStr = QStringLiteral("Female");
        }
        // Unspecified (or anything else) exports as "" = no gender detail
        // (the write path only ever stores Male/Female anyway).
        f.insert(QStringLiteral("gender"), genderStr);
        // Device avatar: export only when it differs from the persisted
        // download baseline (missing baseline = pre-feature row or fresh
        // avatar → include; conversion failure → omit, server copy wins).
        // Untouched avatars stay omitted: no re-upload churn and no QUrl
        // echo-fidelity risk on the download round-trip. Explicitly
        // REMOVED avatars (baseline present, now gone) set photo_removed
        // so the rebuild emits a bare PHOTO: line (WebClients deletion
        // expression — an empty photos list alone would carry the server
        // copy instead). Diagnostics (counts/lengths only, never avatar
        // contents — data URIs are personal data).
        const QList<QtContacts::QContactAvatar> avatarDetails =
            c.details<QtContacts::QContactAvatar>();
        // App edits accumulate avatar details (a removal leaves the stale
        // one behind instead of replacing it): the LAST detail is the
        // freshest write, so it — not .first() — decides presence.
        const QString avatarStr = avatarDetails.isEmpty()
            ? QString()
            : avatarDetails.last().imageUrl().toString();
        if (!guid.isEmpty()) {
            proton_log(QStringLiteral("Contacts avatar uid=%1 n=%2 len=%3 baseline=%4 dirty=%5")
                       .arg(guid)
                       .arg(avatarDetails.size())
                       .arg(avatarStr.size())
                       .arg(photosBaseline.contains(qid) ? 1 : 0)
                       .arg(dirty ? 1 : 0));
        }
        if (!avatarStr.isEmpty()
            && (!photosBaseline.contains(qid)
                || photosBaseline.value(qid).toString() != avatarStr)) {
            const QString dataUri = avatarToDataUri(avatarStr);
            if (!dataUri.isEmpty()) {
                QJsonArray photosArr;
                photosArr.append(dataUri);
                f.insert(QStringLiteral("photos"), photosArr);
            }
        } else if (avatarStr.isEmpty() && !guid.isEmpty()
                   && (!photosBaseline.contains(qid)
                       || !photosBaseline.value(qid).toString().isEmpty())) {
            // Known row, no avatar now: removed (baseline present), or
            // first cycle after upgrade/clear with no baseline to compare
            // against — flagging is safe either way (a bare PHOTO: is a
            // no-op where the server holds no photo). Never-synced rows
            // (no guid) never flag: nothing exists server-side to clear.
            f.insert(QStringLiteral("photo_removed"), true);
        }
        o.insert(QStringLiteral("fields"), f);
        out.append(o);
    }
    return out;
}

void ProtonContactsPlugin::persistContactsAnchors(const QString &anchorsJson) {
    if (anchorsJson.isEmpty()) {
        return;
    }
    proton_log(QStringLiteral("Persisted contacts anchors: %1").arg(anchorsJson.left(2000)));
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    settings.setValue(QStringLiteral("contacts_anchors"), anchorsJson);
    settings.endGroup();
}

void ProtonContactsPlugin::persistContactsPending(const QString &pendingJson) {
    // Wholesale overwrite (never merge): empty clears confirmed/stale
    // entries. Cap logged length like the anchors line.
    if (!pendingJson.isEmpty()) {
        proton_log(QStringLiteral("Persisted contacts pending: %1").arg(pendingJson.left(2000)));
    }
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    settings.setValue(QStringLiteral("contacts_pending"), pendingJson);
    settings.endGroup();
}

QString ProtonContactsPlugin::loadContactsAnchors() {
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    QString a = settings.value(QStringLiteral("contacts_anchors")).toString();
    settings.endGroup();
    return a;
}

QStringList ProtonContactsPlugin::loadContactsKnownUids() {
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    QVariantMap map;
    QJsonDocument doc = QJsonDocument::fromJson(
        settings.value(QStringLiteral("contacts_id_map")).toString().toUtf8());
    if (doc.isObject()) map = doc.toVariant().toMap();
    settings.endGroup();
    return map.keys();
}

QtContacts::QContactCollection ProtonContactsPlugin::findOrCreateCollection()
{
    QString collectionRemoteUid = QStringLiteral("proton-contacts-%1").arg(m_accountId);
    QString collectionName = QStringLiteral("Proton Contacts (%1)").arg(m_accountId);

    QList<QtContacts::QContactCollection> collections = m_manager->collections();
    for (const QtContacts::QContactCollection &col : collections) {
        QVariantMap extended = col.metaData(QtContacts::QContactCollection::KeyExtended).toMap();
        if (extended.value(QStringLiteral("remote_uid")).toString() == collectionRemoteUid) {
            proton_log(QStringLiteral("Found existing Proton collection for account ") + m_accountId);
            return col;
        }
    }

    QtContacts::QContactCollection collection;
    collection.setMetaData(QtContacts::QContactCollection::KeyName, collectionName);
    QVariantMap extended;
    extended.insert(QStringLiteral("remote_uid"), collectionRemoteUid);
    extended.insert(QStringLiteral("account_id"), m_accountId);
    collection.setMetaData(QtContacts::QContactCollection::KeyExtended, extended);

    if (!m_manager->saveCollection(&collection)) {
        proton_log(QStringLiteral("Failed to create Proton contacts collection, error=") + QString::number(static_cast<int>(m_manager->error())));
        return QtContacts::QContactCollection();
    }

    proton_log(QStringLiteral("Created Proton contacts collection for account ") + m_accountId);
    return collection;
}

void ProtonContactsPlugin::persistTokens(const QString &refreshToken, const QString &uid)
{
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    settings.setValue(QStringLiteral("refresh_token"), refreshToken);
    settings.setValue(QStringLiteral("uid"), uid);
    settings.endGroup();
    proton_log(QStringLiteral("Persisted tokens for account ") + m_accountId);
}

QPair<QString, QString> ProtonContactsPlugin::loadPersistedTokens()
{
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    QString refreshToken = settings.value(QStringLiteral("refresh_token")).toString();
    QString uid = settings.value(QStringLiteral("uid")).toString();
    settings.endGroup();
    return qMakePair(refreshToken, uid);
}

// ---- Calendar (single .so, single Sync Protocol "proton") ----
// Real implementation: SignOn (NoUserInteraction) → Rust CalendarSyncEngine
// (bootstrap → unlock → windowed decrypt → JSON) → QOrganizer mkcal.
// Mirrors ProtonContactsPlugin credential handling; per-account collection
// "Proton Calendar (<accountId>)", full-replacement sync via namespaced UID
// "proton-cal-<accountId>-<rawUid>" (namespacedUid(); raw Proton UIDs are
// account-independent and clash across re-created accounts – see
// FINDINGS_CALENDAR.md). Recurrence limited to FREQ daily/weekly/
// monthly/yearly v1 – see FINDINGS_CALENDAR.md).
static const QString PROTON_CALDAV_SERVICE_NAME = QStringLiteral("proton-caldav");

ProtonCalendarPlugin::ProtonCalendarPlugin(const QString &aPluginName,
                                           const Buteo::SyncProfile &aProfile,
                                           Buteo::PluginCbInterface *aCbInterface)
    : Buteo::ClientPlugin(aPluginName, aProfile, aCbInterface)
{
    proton_log(QStringLiteral("ProtonCalendarPlugin constructed: ") + aPluginName + " profile=" + getProfileName());
}
ProtonCalendarPlugin::~ProtonCalendarPlugin() {
    if (m_calEngine) {
        proton_calendar_destroy_engine(m_calEngine);
        m_calEngine = nullptr;
    }
}
bool ProtonCalendarPlugin::init() {
    proton_log(QStringLiteral("ProtonCalendarPlugin::init() profile=") + getProfileName());
    // Storage backend is mKCal + KCalendarCore (the documented Sailfish stack;
    // QtOrganizer is not shipped on this image). Probe open here so failures
    // surface at init instead of mid-sync.
    mKCal::ExtendedCalendar::Ptr cal(new mKCal::ExtendedCalendar(QTimeZone::systemTimeZone()));
    mKCal::ExtendedStorage::Ptr storage = mKCal::ExtendedCalendar::defaultStorage(cal);
    if (!storage->open()) {
        proton_log(QStringLiteral("ProtonCalendarPlugin::init() mKCal storage open failed"));
    } else {
        proton_log(QStringLiteral("ProtonCalendarPlugin::init() mKCal ready, notebooks=") + QString::number(storage->notebooks().size()));
        mKCal::SqliteStorage::Ptr sql = storage.dynamicCast<mKCal::SqliteStorage>();
        if (sql) {
            proton_log(QStringLiteral("ProtonCalendarPlugin::init() mKCal db=") + sql->databaseName());
        }
    }
    m_accountId = iProfile.key(QStringLiteral("accountid"));
    if (m_accountId.isEmpty()) {
        QString profileName = getProfileName();
        QRegularExpression re("-(\\d+)$");
        QRegularExpressionMatch match = re.match(profileName);
        if (match.hasMatch()) {
            m_accountId = match.captured(1);
        }
    }
    if (m_accountId.isEmpty()) {
        m_accountId = iProfile.key(QStringLiteral("account_id"));
    }
    if (m_accountId.isEmpty()) {
        proton_log(QStringLiteral("ERROR: Cannot determine accountid for calendar"));
        return false;
    }
    m_accountManager = new Accounts::Manager(this);
    if (!m_accountManager) {
        return false;
    }
    m_inited = true;
    return requestCalendarCredentials();
}
bool ProtonCalendarPlugin::uninit() {
    m_purgeableUids.clear();
    if (m_calTimer) {
        m_calTimer->stop();
        delete m_calTimer;
        m_calTimer = nullptr;
    }
    if (m_calEngine) {
        proton_calendar_destroy_engine(m_calEngine);
        m_calEngine = nullptr;
    }
    m_credentialsReady = false;
    m_inited = false;
    return true;
}
bool ProtonCalendarPlugin::requestCalendarCredentials() {
    Accounts::AccountId accId = static_cast<Accounts::AccountId>(m_accountId.toUInt());
    Accounts::Account *account = Accounts::Account::fromId(m_accountManager, accId, this);
    if (!account) {
        proton_log(QStringLiteral("ERROR: Unable to load account ") + m_accountId);
        return false;
    }
    Accounts::Service service = m_accountManager->service(PROTON_CALDAV_SERVICE_NAME);
    if (!service.isValid()) {
        // Shared identity lives on the contacts service; fall back.
        service = m_accountManager->service(PROTON_SERVICE_NAME);
    }
    if (!service.isValid()) {
        proton_log(QStringLiteral("ERROR: Unable to find calendar/contacts service"));
        return false;
    }
    account->selectService(service);
    Accounts::AccountService *accountService = new Accounts::AccountService(account, service, this);
    Accounts::AuthData authData = accountService->authData();
    quint32 credentialsId = authData.credentialsId();
    if (credentialsId == 0) {
        account->selectService(service);
        QVariant raw = account->value(QStringLiteral("CredentialsId"));
        if (raw.isValid() && raw.toUInt() > 0) {
            credentialsId = raw.toUInt();
            account->setCredentialsId(credentialsId);
            account->sync();
        }
    }
    if (credentialsId == 0) {
        account->selectService(Accounts::Service());
        credentialsId = account->credentialsId();
        if (credentialsId > 0) {
            account->selectService(service);
        }
    }
    m_identity = SignOn::Identity::existingIdentity(credentialsId, this);
    if (!m_identity) {
        return false;
    }
    m_authSession = m_identity->createSession(authData.method());
    if (!m_authSession) {
        return false;
    }
    connect(m_authSession, &SignOn::AuthSession::response,
            this, &ProtonCalendarPlugin::onCalendarSignOnResponse);
    connect(m_authSession, &SignOn::AuthSession::error,
            this, &ProtonCalendarPlugin::onCalendarSignOnError);
    SignOn::SessionData sessionData;
    sessionData.setUiPolicy(SignOn::NoUserInteractionPolicy);
    m_authSession->process(sessionData, authData.mechanism());
    return true;
}
void ProtonCalendarPlugin::onCalendarSignOnResponse(const SignOn::SessionData &data) {
    bool twoFARequired = data.getProperty(QStringLiteral("TwoFARequired")).toBool();
    if (twoFARequired) {
        emit error(getProfileName(), QStringLiteral("Two-factor authentication required – please update credentials in Settings → Proton and enter OTP code"), Buteo::SyncResults::AUTHENTICATION_FAILURE);
        return;
    }
    QString username = data.UserName();
    QString userNameViaProperty = data.getProperty(QStringLiteral("UserName")).toString();
    if (username.isEmpty() && !userNameViaProperty.isEmpty()) username = userNameViaProperty;
    QString accessToken = data.getProperty(QStringLiteral("AccessToken")).toString();
    QString refreshToken = data.getProperty(QStringLiteral("RefreshToken")).toString();
    QString uid = data.getProperty(QStringLiteral("Uid")).toString();
    QString derivedJson = data.getProperty(QStringLiteral("DerivedPasswords")).toString();
    if (refreshToken.isEmpty() || uid.isEmpty()) {
        auto tokens = loadPersistedCalendarTokens();
        if (refreshToken.isEmpty()) refreshToken = tokens.first;
        if (uid.isEmpty()) uid = tokens.second;
    }
    if (derivedJson.isEmpty()) {
        derivedJson = loadMergedDerivedPasswords(m_accountId, uid, username, QString());
    } else {
        proton_log(QStringLiteral("Calendar: DerivedPasswords from SignOn blob"));
        QString merged = loadMergedDerivedPasswords(m_accountId, uid, username, derivedJson);
        if (!merged.isEmpty()) {
            derivedJson = merged;
        }
    }
    if (accessToken.isEmpty() && refreshToken.isEmpty()) {
        emit error(getProfileName(), QStringLiteral("No auth tokens received"), Buteo::SyncResults::AUTHENTICATION_FAILURE);
        return;
    }
    // Upsync inputs: local inventory (live rows + tombstones) and the
    // persisted anchor map. Empty inventory = download-only, identical to
    // the old constructor path (malformed JSON degrades the same way).
    QJsonArray inventory = exportLocalInventory();
    QByteArray inventoryJson =
        QJsonDocument(inventory).toJson(QJsonDocument::Compact);
    proton_log(QStringLiteral("Calendar inventory: %1 live/tombstone rows").arg(inventory.size()));
    m_calEngine = proton_calendar_create_engine_with_inventory(
        username.toUtf8().constData(),
        accessToken.toUtf8().constData(),
        refreshToken.toUtf8().constData(),
        uid.toUtf8().constData(),
        derivedJson.toUtf8().constData(),
        loadCalendarDefaults().toUtf8().constData(),
        inventoryJson.constData(),
        loadUpsyncAnchors().toUtf8().constData());
    if (!m_calEngine) {
        emit error(getProfileName(), QStringLiteral("Failed to create calendar engine"), Buteo::SyncResults::INTERNAL_ERROR);
        return;
    }
    m_credentialsReady = true;
    m_calTimer = new QTimer(this);
    connect(m_calTimer, &QTimer::timeout, this, &ProtonCalendarPlugin::pollCalendarStatus);
    if (!startSync()) {
        emit error(getProfileName(), QStringLiteral("Failed to start calendar sync"), Buteo::SyncResults::INTERNAL_ERROR);
    }
}
void ProtonCalendarPlugin::onCalendarSignOnError(const SignOn::Error &signOnError) {
    emit error(getProfileName(), QStringLiteral("Authentication failed: ") + signOnError.message(), Buteo::SyncResults::AUTHENTICATION_FAILURE);
}
bool ProtonCalendarPlugin::startSync() {
    if (!m_credentialsReady) {
        return true;
    }
    if (!m_calEngine) {
        emit error(getProfileName(), QStringLiteral("Calendar engine not initialized"), Buteo::SyncResults::INTERNAL_ERROR);
        return false;
    }
    if (!proton_calendar_start_sync(m_calEngine)) {
        emit error(getProfileName(), QStringLiteral("Failed to start calendar sync"), Buteo::SyncResults::INTERNAL_ERROR);
        return false;
    }
    m_calTimer->start(500);
    return true;
}
void ProtonCalendarPlugin::pollCalendarStatus() {
    if (!m_calEngine) return;
    ProtonBridgeStatus status;
    proton_calendar_get_status(m_calEngine, &status);
    QString state = QString::fromUtf8(reinterpret_cast<const char*>(status.state),
                                      strnlen(reinterpret_cast<const char*>(status.state), 16));
    if (state == QLatin1String("complete")) {
        m_calTimer->stop();
        char *rt = proton_calendar_get_refresh_token(m_calEngine);
        char *uid = proton_calendar_get_uid(m_calEngine);
        if (rt && uid) {
            persistCalendarTokens(QString::fromUtf8(rt), QString::fromUtf8(uid));
        }
        if (rt) proton_bridge_free_string(rt);
        if (uid) proton_bridge_free_string(uid);
        char *keysDbg = proton_calendar_get_keys_debug(m_calEngine);
        if (keysDbg) {
            proton_log(QStringLiteral("Calendar keys debug: ") + QString::fromUtf8(keysDbg));
            proton_bridge_free_string(keysDbg);
        }
        char *defaults = proton_calendar_get_defaults_json(m_calEngine);
        if (defaults) {
            persistCalendarDefaults(QString::fromUtf8(defaults));
            proton_bridge_free_string(defaults);
        }
        // Upsync outputs (only meaningful on `complete`, which is where we
        // are): anchors persist wholesale (null/empty never clobbers — the
        // getter returns null then), purgeable feeds the selective purge in
        // writeEventsToMkCal below, conflicts notify server-wins.
        char *anchors = proton_calendar_get_anchors_json(m_calEngine);
        if (anchors) {
            persistUpsyncAnchors(QString::fromUtf8(anchors));
            proton_bridge_free_string(anchors);
        }
        // Posted-but-unconfirmed creates persist wholesale on complete too
        // (normally empty then — the drain above already cleared them — but
        // write it regardless so stale entries can never linger).
        char *pending = proton_calendar_get_pending_json(m_calEngine);
        persistCalendarPending(pending ? QString::fromUtf8(pending) : QString());
        if (pending) proton_bridge_free_string(pending);
        m_purgeableUids.clear();
        char *purgeable = proton_calendar_get_purgeable_json(m_calEngine);
        if (purgeable) {
            QJsonDocument doc = QJsonDocument::fromJson(QByteArray(purgeable));
            proton_bridge_free_string(purgeable);
            if (doc.isArray()) {
                for (const QJsonValue &v : doc.array()) {
                    if (v.isString()) m_purgeableUids.insert(v.toString());
                }
            }
        }
        char *conflicts = proton_calendar_get_conflicts_json(m_calEngine);
        if (conflicts) {
            QJsonDocument doc = QJsonDocument::fromJson(QByteArray(conflicts));
            proton_bridge_free_string(conflicts);
            if (doc.isArray() && !doc.array().isEmpty()) {
                sendProtonNotification(
                    QStringLiteral("Proton Calendar sync conflicts"),
                    QStringLiteral("%1 events changed on both sides; server version kept").arg(doc.array().size()));
            }
        }
        char *json = proton_calendar_get_events_json(m_calEngine);
        if (json) {
            QByteArray jsonData(json);
            proton_bridge_free_string(json);
            if (writeEventsToMkCal(jsonData)) {
                emit success(getProfileName(), QStringLiteral("Calendar sync completed"));
            } else {
                emit error(getProfileName(), QStringLiteral("Failed to write calendar events"), Buteo::SyncResults::INTERNAL_ERROR);
                sendProtonNotification(QStringLiteral("Proton Calendar sync failed"), QStringLiteral("Failed to write events to phone"));
            }
        } else {
            emit success(getProfileName(), QStringLiteral("Calendar sync completed (no events)"));
        }
    } else if (state == QLatin1String("error")) {
        m_calTimer->stop();
        QString errMsg = QString::fromUtf8(reinterpret_cast<const char*>(status.error),
                                           strnlen(reinterpret_cast<const char*>(status.error), 256));
        proton_log(QStringLiteral("Calendar sync error: ") + errMsg);
        // The error path is exactly when posted-but-unconfirmed creates
        // exist (e.g. re-list failed after successful POSTs): persist the
        // pending retry UIDs wholesale so the next cycle reuses them.
        char *pending = proton_calendar_get_pending_json(m_calEngine);
        persistCalendarPending(pending ? QString::fromUtf8(pending) : QString());
        if (pending) proton_bridge_free_string(pending);
        sendProtonNotification(QStringLiteral("Proton Calendar sync failed"), errMsg);
        emit error(getProfileName(), errMsg, Buteo::SyncResults::AUTHENTICATION_FAILURE);
    }
}
// Forward: version-independent unix→UTC (defined with the other file-local
// helpers below; needed by parseCalTime).
static QDateTime utcFromUnix(qint64 secs);
QDateTime ProtonCalendarPlugin::parseCalTime(const QString &ical, qint64 unixFallback, const QString &tz) {
    // Accept UTC (…Z), floating, DATE-only, and TZID-stripped values (parse_ical
    // already strips params). Fall back to row unix time + timezone.
    auto parseFormats = [&](const QString &v) -> QDateTime {
        QString s = v.trimmed();
        if (s.isEmpty()) return QDateTime();
        // DATE-only all-day.
        if (s.length() == 8 && !s.contains('T')) {
            QDate d = QDate::fromString(s, QStringLiteral("yyyyMMdd"));
            if (d.isValid()) return QDateTime(d, QTime(0, 0), Qt::UTC);
        }
        QStringList fmts = { QStringLiteral("yyyyMMdd'T'HHmmss'Z'"), QStringLiteral("yyyyMMdd'T'HHmmss"), QStringLiteral("yyyy-MM-ddTHH:mm:ss'Z'"), QStringLiteral("yyyy-MM-ddTHH:mm:ss") };
        for (const QString &f : fmts) {
            QDateTime dt = QDateTime::fromString(s, f);
            if (dt.isValid()) {
                if (s.endsWith('Z')) dt.setTimeSpec(Qt::UTC);
                return dt;
            }
        }
        return QDateTime();
    };
    QDateTime dt = parseFormats(ical);
    if (dt.isValid()) {
        // Floating wall-clock + known event timezone (e.g. TZID-stripped
        // "20260914T200000" + StartTimezone Europe/Rome): attach the zone so
        // occurrence instants match the server's recurrenceId instants
        // (T15 exception linkage, verified live 2026-09-06).
        if (!ical.trimmed().endsWith('Z') && dt.timeSpec() == Qt::LocalTime
            && !tz.isEmpty() && tz != QStringLiteral("UTC")) {
            QTimeZone zone(tz.toUtf8());
            if (zone.isValid()) {
                QDateTime zoned(dt.date(), dt.time(), zone);
                if (zoned.isValid()) return zoned;
            }
        }
        return dt;
    }
    if (unixFallback > 0) {
        // Qt 5.6 (Sailfish): no fromSecsSinceEpoch (Qt 5.8+); use the
        // version-independent UTC construction (see utcFromUnix).
        return utcFromUnix(unixFallback);
    }
    return QDateTime();
}
QString ProtonCalendarPlugin::findOrCreateNotebook(mKCal::ExtendedCalendar::Ptr cal,
                                                       mKCal::ExtendedStorage::Ptr storage,
                                                       const QString &calId,
                                                       const QString &calName) {
    Q_UNUSED(cal);
    // One notebook per Proton calendar (T20 "porcodio" must be visibly
    // separate). Legacy single notebook from the first version is cleaned
    // up by the caller.
    QString nbUid = QStringLiteral("proton-calendar-%1-%2").arg(m_accountId, calId);
    mKCal::Notebook::List nbs = storage->notebooks();
    for (const mKCal::Notebook::Ptr &nb : nbs) {
        if (nb && nb->uid() == nbUid) {
            return nbUid;
        }
    }
    mKCal::Notebook::Ptr nb(new mKCal::Notebook());
    nb->setUid(nbUid);
    nb->setName(calName.isEmpty() ? QStringLiteral("Proton Calendar (%1)").arg(m_accountId) : calName);
    nb->setDescription(QStringLiteral("Proton Calendar"));
    nb->setPluginName(QStringLiteral("proton"));
    nb->setAccount(m_accountId);
    nb->setSyncProfile(getProfileName());
    nb->setIsVisible(true);
    nb->setIsReadOnly(false);
    nb->setEventsAllowed(true);
    nb->setTodosAllowed(false);
    nb->setJournalsAllowed(false);
    if (!storage->addNotebook(nb)) {
        proton_log(QStringLiteral("Failed to create calendar notebook ") + nbUid);
        return QString();
    }
    proton_log(QStringLiteral("Created calendar notebook ") + nbUid);
    return nbUid;
}
// mKCal enforces UNIQUE incidence UIDs across the whole storage, but the
// Proton/ical UID is account-independent: re-creating the account (104 →
// 105) re-inserts the same UIDs next to the orphaned notebooks and the
// batch INSERT fails, rolling back the entire save() (verified 2026-09-06:
// deterministic "mKCal storage save failed"). Namespace every stored UID
// by account; lookups must use the same form.
QString ProtonCalendarPlugin::namespacedUid(const QString &raw) const {
    return QStringLiteral("proton-cal-%1-%2").arg(m_accountId, raw);
}

static QString stripMailto(const QString &s) {
    QString email = s.trimmed();
    int mailto = email.toLower().indexOf(QStringLiteral("mailto:"));
    if (mailto >= 0) {
        email = email.mid(mailto + 7).split(';').first().trimmed();
    }
    return email;
}

// Unambiguous unix→UTC conversion. QDateTime::fromTime_t + setTimeSpec
// round-trips through local time on some Qt versions (observed +2h shift on
// device Qt 5.6: rid 20:00Z became 22:00Z, breaking recursAt linkage, while
// host Qt kept the instant). Epoch + addSecs is identical everywhere.
static QDateTime utcFromUnix(qint64 secs) {
    QDateTime dt(QDate(1970, 1, 1), QTime(0, 0, 0), Qt::UTC);
    return dt.addSecs(secs);
}

// RFC5545 weekday → KCalendarCore day number (WDayPos: 1=Monday..7=Sunday).
static int weekdayNumber(const QString &day) {
    if (day == QLatin1String("MO")) return 1;
    if (day == QLatin1String("TU")) return 2;
    if (day == QLatin1String("WE")) return 3;
    if (day == QLatin1String("TH")) return 4;
    if (day == QLatin1String("FR")) return 5;
    if (day == QLatin1String("SA")) return 6;
    if (day == QLatin1String("SU")) return 7;
    return 0;
}

// Parse one BYDAY entry ("MO", "1FR", "-1SU", "+2TU") into WDayPos parts.
// Returns false for garbage (unknown weekday, non-numeric prefix).
static bool parseByDayEntry(const QString &entry, int &posOut, int &dayOut) {
    QString e = entry.trimmed().toUpper();
    if (e.length() < 2) return false;
    QString day = e.right(2);
    int dayNum = weekdayNumber(day);
    if (dayNum == 0) return false;
    QString num = e.left(e.length() - 2);
    if (num.isEmpty()) {
        posOut = 0;
        dayOut = dayNum;
        return true;
    }
    bool ok = false;
    int pos = num.toInt(&ok);
    if (!ok) return false;
    posOut = pos;
    dayOut = dayNum;
    return true;
}

// Comma-separated integer list clamped to [lo,hi], deduped, order-kept.
static QList<int> parseIntList(const QString &value, int lo, int hi) {
    QList<int> out;
    for (const QString &entry : value.split(',')) {
        bool ok = false;
        int n = entry.trimmed().toInt(&ok);
        if (ok && n >= lo && n <= hi && !out.contains(n)) out.append(n);
    }
    return out;
}

static KCalendarCore::Attendee::PartStat mapPartStat(const QString &s) {
    if (s == QLatin1String("ACCEPTED")) return KCalendarCore::Attendee::Accepted;
    if (s == QLatin1String("DECLINED")) return KCalendarCore::Attendee::Declined;
    if (s == QLatin1String("TENTATIVE")) return KCalendarCore::Attendee::Tentative;
    if (s == QLatin1String("DELEGATED")) return KCalendarCore::Attendee::Delegated;
    if (s == QLatin1String("COMPLETED")) return KCalendarCore::Attendee::Completed;
    if (s == QLatin1String("IN-PROCESS")) return KCalendarCore::Attendee::InProcess;
    if (s == QLatin1String("NEEDS-ACTION")) return KCalendarCore::Attendee::NeedsAction;
    return KCalendarCore::Attendee::None;
}

static KCalendarCore::Attendee::Role mapAttendeeRole(const QString &s) {
    if (s == QLatin1String("CHAIR")) return KCalendarCore::Attendee::Chair;
    if (s == QLatin1String("OPT-PARTICIPANT")) return KCalendarCore::Attendee::OptParticipant;
    if (s == QLatin1String("NON-PARTICIPANT")) return KCalendarCore::Attendee::NonParticipant;
    return KCalendarCore::Attendee::ReqParticipant;
}

static QString weekdayCode(int day) {
    switch (day) {
    case 1: return QStringLiteral("MO");
    case 2: return QStringLiteral("TU");
    case 3: return QStringLiteral("WE");
    case 4: return QStringLiteral("TH");
    case 5: return QStringLiteral("FR");
    case 6: return QStringLiteral("SA");
    case 7: return QStringLiteral("SU");
    default: return QString();
    }
}

static QString intList(const QList<int> &nums) {
    QStringList parts;
    for (int n : nums) parts << QString::number(n);
    return parts.join(',');
}

// Signed offset seconds → Proton ISO8601 duration Trigger ("-PT15M").
// Weeks/days/time split greedily; zero → "-PT0S". Positive (after-start)
// offsets keep a '+'-less unsigned form, mirroring parse_notification_trigger.
static QString durationTrigger(qint64 offsetSecs) {
    bool neg = offsetSecs < 0;
    qint64 mag = neg ? -offsetSecs : offsetSecs;
    qint64 weeks = mag / 604800;
    mag %= 604800;
    qint64 days = mag / 86400;
    mag %= 86400;
    qint64 hours = mag / 3600;
    mag %= 3600;
    qint64 minutes = mag / 60;
    qint64 seconds = mag % 60;
    // ISO8601 forbids mixing W with other units: fold weeks into days
    // unless the whole offset is exact weeks.
    if (weeks > 0 && (days > 0 || hours > 0 || minutes > 0 || seconds > 0)) {
        days += weeks * 7;
        weeks = 0;
    }
    if (weeks > 0) {
        return (neg ? QStringLiteral("-") : QString())
            + QStringLiteral("P%1W").arg(weeks);
    }
    QString out = QStringLiteral("P");
    if (days > 0) out += QStringLiteral("%1D").arg(days);
    QString time;
    if (hours > 0) time += QStringLiteral("%1H").arg(hours);
    if (minutes > 0) time += QStringLiteral("%1M").arg(minutes);
    if (seconds > 0 || (days == 0 && hours == 0 && minutes == 0)) {
        time += QStringLiteral("%1S").arg(seconds);
    }
    if (!time.isEmpty()) out += QStringLiteral("T") + time;
    return (neg ? QStringLiteral("-") : QString()) + out;
}

// Serialize a KCalendarCore recurrence rule to an RFC5545 RRULE string for
// the upsync inventory (common subset only: FREQ D/W/M/Y + INTERVAL +
// COUNT/UNTIL + BYDAY/BYMONTHDAY/BYMONTH/BYSETPOS + WKST). Anything else
// (sub-daily FREQ, BYHOUR/MINUTE/SECOND, BYYEARDAY/BYWEEKNO) is
// unserializable: hasRecurrence=true with an empty rule, so the engine
// keeps the server rule on update (phone edit reverts on download,
// documented) and defers creates (never flatten a series silently).
// RRULE with both COUNT and UNTIL is likewise unserializable (server
// rejects the combo).
static QString serializeRrule(KCalendarCore::RecurrenceRule *rule, bool *hasRecurrence) {
    *hasRecurrence = false;
    if (!rule || rule->recurrenceType() == KCalendarCore::RecurrenceRule::rNone) {
        return QString();
    }
    *hasRecurrence = true;
    QString freq;
    switch (rule->recurrenceType()) {
    case KCalendarCore::RecurrenceRule::rDaily: freq = QStringLiteral("DAILY"); break;
    case KCalendarCore::RecurrenceRule::rWeekly: freq = QStringLiteral("WEEKLY"); break;
    case KCalendarCore::RecurrenceRule::rMonthly: freq = QStringLiteral("MONTHLY"); break;
    case KCalendarCore::RecurrenceRule::rYearly: freq = QStringLiteral("YEARLY"); break;
    default: return QString(); // sub-daily: not server-mappable
    }
    if (!rule->byHours().isEmpty() || !rule->byMinutes().isEmpty()
        || !rule->bySeconds().isEmpty() || !rule->byYearDays().isEmpty()
        || !rule->byWeekNumbers().isEmpty()) {
        return QString();
    }
    QString rrule = QStringLiteral("FREQ=") + freq;
    if (rule->frequency() > 1) {
        rrule += QStringLiteral(";INTERVAL=") + QString::number(rule->frequency());
    }
    bool hasCount = rule->duration() > 0;
    bool hasUntil = rule->endDt().isValid();
    if (hasCount && hasUntil) return QString();
    if (hasCount) {
        rrule += QStringLiteral(";COUNT=") + QString::number(rule->duration());
    } else if (hasUntil) {
        QDateTime until = rule->endDt().toUTC();
        rrule += QStringLiteral(";UNTIL=") + until.toString(QStringLiteral("yyyyMMdd'T'HHmmss'Z'"));
    }
    if (!rule->byDays().isEmpty()) {
        QStringList days;
        for (const KCalendarCore::RecurrenceRule::WDayPos &wp : rule->byDays()) {
            QString code = weekdayCode(wp.day());
            if (code.isEmpty()) return QString();
            days << (wp.pos() == 0 ? code : QString::number(wp.pos()) + code);
        }
        rrule += QStringLiteral(";BYDAY=") + days.join(',');
    }
    if (!rule->byMonthDays().isEmpty()) {
        rrule += QStringLiteral(";BYMONTHDAY=") + intList(rule->byMonthDays());
    }
    if (!rule->byMonths().isEmpty()) {
        rrule += QStringLiteral(";BYMONTH=") + intList(rule->byMonths());
    }
    if (!rule->bySetPos().isEmpty()) {
        rrule += QStringLiteral(";BYSETPOS=") + intList(rule->bySetPos());
    }
    QString wkst = weekdayCode(rule->weekStart());
    if (!wkst.isEmpty()) {
        rrule += QStringLiteral(";WKST=") + wkst;
    }
    return rrule;
}

// Fill a KCalendarCore event from one JSON row (times precomputed by caller).
// Recurrence linkage (recurrenceId) is handled by the caller: pass 1 adds
// masters, pass 2 decomposes exceptions into EXDATE + standalone (T15).
//
// Recurrence (RFC5545 §3.3.10, verified T09–T14 plus BYDAY/INTERVAL matrix):
// FREQ + INTERVAL + COUNT/UNTIL + BYDAY/BYMONTHDAY/BYMONTH/BYYEARDAY/
// BYWEEKNO/BYSETPOS/WKST. BYHOUR/BYMINUTE/BYSECOND are intentionally ignored
// (time comes from DTSTART). Invalid parts are skipped, never failing the
// event. COUNT wins over UNTIL when both appear (RFC forbids the combo).
static void fillEventFromJson(const KCalendarCore::Event::Ptr &ev, const QJsonObject &o,
                              const QString &uid, const QDateTime &start, const QDateTime &end,
                              bool fullDay) {
    ev->setUid(uid);
    // Server row ID for future upsync change detection (planner input):
    // local inventory maps mKCal UID → this ID to build update/delete ops.
    // Stored for masters and decomposed exception standalones alike (the
    // exception row carries its OWN id). Read back via
    // customProperty("PROTON", "EVENT-ID") when exporting deltas.
    QString protonId = o.value(QLatin1String("id")).toString();
    if (!protonId.isEmpty()) {
        ev->setCustomProperty("PROTON", "EVENT-ID", protonId);
    }
    QString summary = o.value(QLatin1String("summary")).toString();
    ev->setSummary(summary.isEmpty() ? uid : summary);
    ev->setDescription(o.value(QLatin1String("description")).toString());
    ev->setLocation(o.value(QLatin1String("location")).toString());
    ev->setAllDay(fullDay);
    ev->setDtStart(start);
    ev->setDtEnd(end);
    QString startTz = o.value(QLatin1String("start_timezone")).toString();
    if (startTz.isEmpty()) startTz = QStringLiteral("UTC");
    QString rrule = o.value(QLatin1String("rrule")).toString().toUpper();
    if (rrule.contains(QStringLiteral("FREQ="))) {
        KCalendarCore::RecurrenceRule::PeriodType period =
            KCalendarCore::RecurrenceRule::rNone;
        if (rrule.contains(QStringLiteral("FREQ=DAILY"))) period = KCalendarCore::RecurrenceRule::rDaily;
        else if (rrule.contains(QStringLiteral("FREQ=WEEKLY"))) period = KCalendarCore::RecurrenceRule::rWeekly;
        else if (rrule.contains(QStringLiteral("FREQ=MONTHLY"))) period = KCalendarCore::RecurrenceRule::rMonthly;
        else if (rrule.contains(QStringLiteral("FREQ=YEARLY"))) period = KCalendarCore::RecurrenceRule::rYearly;
        else if (rrule.contains(QStringLiteral("FREQ=HOURLY"))) period = KCalendarCore::RecurrenceRule::rHourly;
        else if (rrule.contains(QStringLiteral("FREQ=MINUTELY"))) period = KCalendarCore::RecurrenceRule::rMinutely;
        else if (rrule.contains(QStringLiteral("FREQ=SECONDLY"))) period = KCalendarCore::RecurrenceRule::rSecondly;
        if (period != KCalendarCore::RecurrenceRule::rNone) {
            KCalendarCore::RecurrenceRule *rule = new KCalendarCore::RecurrenceRule();
            rule->setRecurrenceType(period);
            rule->setFrequency(1);
            rule->setStartDt(start);
            rule->setRRule(rrule); // stored for reference only (see header)
            int count = 0;
            QDateTime until;
            QList<KCalendarCore::RecurrenceRule::WDayPos> byDays;
            QList<int> byMonthDays, byMonths, byYearDays, byWeekNos, bySetPos;
            short wkst = 0;
            for (const QString &part : rrule.split(';')) {
                if (part.startsWith(QStringLiteral("COUNT="))) {
                    bool ok = false;
                    int n = part.mid(6).toInt(&ok);
                    if (ok && n > 0) count = n;
                } else if (part.startsWith(QStringLiteral("UNTIL="))) {
                    QDateTime u = ProtonCalendarPlugin::parseCalTime(part.mid(6), 0, startTz);
                    if (u.isValid()) until = u;
                } else if (part.startsWith(QStringLiteral("INTERVAL="))) {
                    bool ok = false;
                    int n = part.mid(9).toInt(&ok);
                    if (ok && n >= 1) rule->setFrequency(n);
                } else if (part.startsWith(QStringLiteral("BYDAY="))) {
                    for (const QString &entry : part.mid(6).split(',')) {
                        int pos = 0, day = 0;
                        if (!parseByDayEntry(entry, pos, day)) continue;
                        KCalendarCore::RecurrenceRule::WDayPos wp(pos, static_cast<short>(day));
                        if (!byDays.contains(wp)) byDays.append(wp);
                    }
                } else if (part.startsWith(QStringLiteral("BYMONTHDAY="))) {
                    byMonthDays = parseIntList(part.mid(11), -31, 31);
                    byMonthDays.erase(std::remove(byMonthDays.begin(), byMonthDays.end(), 0),
                                      byMonthDays.end());
                } else if (part.startsWith(QStringLiteral("BYMONTH="))) {
                    byMonths = parseIntList(part.mid(8), 1, 12);
                } else if (part.startsWith(QStringLiteral("BYYEARDAY="))) {
                    QList<int> days = parseIntList(part.mid(10), -366, 366);
                    days.erase(std::remove(days.begin(), days.end(), 0), days.end());
                    byYearDays = days;
                } else if (part.startsWith(QStringLiteral("BYWEEKNO="))) {
                    QList<int> weeks = parseIntList(part.mid(9), -53, 53);
                    weeks.erase(std::remove(weeks.begin(), weeks.end(), 0), weeks.end());
                    byWeekNos = weeks;
                } else if (part.startsWith(QStringLiteral("BYSETPOS="))) {
                    QList<int> pos = parseIntList(part.mid(9), -366, 366);
                    pos.erase(std::remove(pos.begin(), pos.end(), 0), pos.end());
                    bySetPos = pos;
                } else if (part.startsWith(QStringLiteral("WKST="))) {
                    int w = weekdayNumber(part.mid(5));
                    if (w >= 1 && w <= 7) wkst = static_cast<short>(w);
                }
            }
            if (!byDays.isEmpty()) rule->setByDays(byDays);
            if (!byMonthDays.isEmpty()) rule->setByMonthDays(byMonthDays);
            if (!byMonths.isEmpty()) rule->setByMonths(byMonths);
            if (!byYearDays.isEmpty()) rule->setByYearDays(byYearDays);
            if (!byWeekNos.isEmpty()) rule->setByWeekNumbers(byWeekNos);
            if (!bySetPos.isEmpty()) rule->setBySetPos(bySetPos);
            if (wkst != 0) rule->setWeekStart(wkst);
            if (count > 0) {
                rule->setDuration(count);
            } else if (until.isValid()) {
                rule->setEndDt(until);
            }
            ev->recurrence()->addRRule(rule); // recurrence takes ownership
        }
    }
    // EXDATEs (T14 single-occurrence deletes). Values are floating when the
    // source line carried TZID (params stripped by Rust), so interpret them
    // in the event's timezone — UTC fallback was a 2h shift for zoned events.
    QJsonArray exdates = o.value(QLatin1String("exdates")).toArray();
    for (const QJsonValue &xv : exdates) {
        QDateTime ex = ProtonCalendarPlugin::parseCalTime(xv.toString(), 0, startTz);
        if (ex.isValid()) ev->recurrence()->addExDateTime(ex);
    }
    // Attendees: prefer structured attendees_full (CN/RSVP/PARTSTAT/ROLE),
    // fall back to the legacy attendees email list (T16).
    QJsonArray full = o.value(QLatin1String("attendees_full")).toArray();
    if (!full.isEmpty()) {
        for (const QJsonValue &av : full) {
            QJsonObject ao = av.toObject();
            QString email = stripMailto(ao.value(QLatin1String("email")).toString());
            if (email.isEmpty()) continue;
            QString name = ao.value(QLatin1String("name")).toString();
            bool rsvp = ao.value(QLatin1String("rsvp")).toBool(false);
            KCalendarCore::Attendee::PartStat st =
                mapPartStat(ao.value(QLatin1String("partstat")).toString().toUpper());
            KCalendarCore::Attendee::Role role =
                mapAttendeeRole(ao.value(QLatin1String("role")).toString().toUpper());
            KCalendarCore::Attendee attendee(name, email, rsvp, st, role);
            QString cutype = ao.value(QLatin1String("cutype")).toString().toUpper();
            if (!cutype.isEmpty()) attendee.setCuType(cutype);
            ev->addAttendee(attendee);
        }
    } else {
        QJsonArray atts = o.value(QLatin1String("attendees")).toArray();
        for (const QJsonValue &av : atts) {
            QString email = stripMailto(av.toString());
            if (email.isEmpty()) continue;
            ev->addAttendee(KCalendarCore::Attendee(QString(), email));
        }
    }
    QString organizerEmail = stripMailto(o.value(QLatin1String("organizer")).toString());
    QString organizerName = o.value(QLatin1String("organizer_name")).toString();
    if (!organizerEmail.isEmpty()) {
        if (organizerName.isEmpty()) {
            ev->setOrganizer(organizerEmail);
        } else {
            ev->setOrganizer(KCalendarCore::Person(organizerName, organizerEmail));
        }
    }
    QString status = o.value(QLatin1String("status")).toString().toUpper();
    if (status == QLatin1String("CONFIRMED")) ev->setStatus(KCalendarCore::Incidence::StatusConfirmed);
    else if (status == QLatin1String("CANCELLED")) ev->setStatus(KCalendarCore::Incidence::StatusCanceled);
    else if (status == QLatin1String("TENTATIVE")) ev->setStatus(KCalendarCore::Incidence::StatusTentative);
    if (o.value(QLatin1String("transp")).toString().compare(QLatin1String("TRANSPARENT"), Qt::CaseInsensitive) == 0) {
        ev->setTransparency(KCalendarCore::Event::Transparent);
    }
        QString color = o.value(QLatin1String("color")).toString();
        if (!color.isEmpty()) ev->setColor(color);
        // Reminders (Proton Notifications tri-state; null = inherit calendar
        // defaults, which the Calendar app applies itself).
        QJsonArray notifs = o.value(QLatin1String("notifications")).toArray();
        for (const QJsonValue &nv : notifs) {
            QJsonObject no = nv.toObject();
            qint64 offSecs = no.value(QLatin1String("offset_secs")).toVariant().toLongLong();
            KCalendarCore::Alarm::Ptr alarm(new KCalendarCore::Alarm(ev.data()));
            if (no.value(QLatin1String("action")).toString() == QLatin1String("email")) {
                alarm->setType(KCalendarCore::Alarm::Email);
            } else {
                alarm->setType(KCalendarCore::Alarm::Display);
            }
            alarm->setStartOffset(KCalendarCore::Duration(static_cast<int>(offSecs),
                                                          KCalendarCore::Duration::Seconds));
            alarm->setEnabled(true);
            ev->addAlarm(alarm);
        }
}

// Shared start/end computation (unix fallback, full-day exclusive-end fix).
static bool eventTimes(const QJsonObject &o, QDateTime &start, QDateTime &end, bool &fullDay) {
    fullDay = o.value(QLatin1String("full_day")).toBool(false);
    start = ProtonCalendarPlugin::parseCalTime(o.value(QLatin1String("dtstart")).toString(),
                                               o.value(QLatin1String("start_time")).toVariant().toLongLong(),
                                               o.value(QLatin1String("start_timezone")).toString());
    end = ProtonCalendarPlugin::parseCalTime(o.value(QLatin1String("dtend")).toString(),
                                             o.value(QLatin1String("end_time")).toVariant().toLongLong(),
                                             o.value(QLatin1String("end_timezone")).toString());
    if (!start.isValid()) start = QDateTime::currentDateTimeUtc();
    if (!end.isValid() || end < start) end = start.addSecs(fullDay ? 86400 : 3600);
    if (fullDay) {
        // Proton/mKCal all-day DTEND is exclusive but the Calendar app reads it
        // inclusive: T03 (1 day) showed 2, T04 (3 days) showed 4 (live 2026-09-06).
        end = end.addDays(-1);
        if (end < start) end = start;
    }
    return true;
}

bool ProtonCalendarPlugin::writeEventsToMkCal(const QByteArray &json) {
    QJsonDocument doc = QJsonDocument::fromJson(json);
    if (!doc.isArray()) {
        proton_log(QStringLiteral("Expected JSON array of events"));
        return false;
    }
    mKCal::ExtendedCalendar::Ptr cal(
        new mKCal::ExtendedCalendar(QTimeZone::systemTimeZone()));
    mKCal::ExtendedStorage::Ptr storage = mKCal::ExtendedCalendar::defaultStorage(cal);
    if (!storage->open()) {
        proton_log(QStringLiteral("mKCal storage open failed"));
        return false;
    }
    QJsonArray arr = doc.array();
    // Validate identities before touching notebooks. Duplicate/empty UIDs
    // cannot be inserted reliably and must not turn replacement into deletion.
    QSet<QString> incomingUids;
    for (const QJsonValue &value : arr) {
        QJsonObject row = value.toObject();
        QString uid = row.value(QLatin1String("uid")).toString();
        qint64 rid = row.value(QLatin1String("recurrence_id")).toVariant().toLongLong();
        QString storedUid = rid > 0 ? QStringLiteral("%1#%2").arg(uid, QString::number(rid)) : uid;
        if (uid.isEmpty() || incomingUids.contains(storedUid)) {
            proton_log(QStringLiteral("Invalid or duplicate calendar event UID; import aborted"));
            return false;
        }
        incomingUids.insert(storedUid);
    }
    // Group rows by Proton calendar (one notebook each, T20 separation).
    QMap<QString, QString> calNames;
    QMap<QString, QList<int>> byCal;
    for (int i = 0; i < arr.size(); ++i) {
        QJsonObject o = arr.at(i).toObject();
        QString cid = o.value(QLatin1String("calendar_id")).toString();
        if (cid.isEmpty()) cid = QStringLiteral("default");
        if (!calNames.contains(cid)) {
            calNames[cid] = o.value(QLatin1String("calendar_name")).toString();
        }
        byCal[cid].append(i);
    }
    // Migration + full replacement: drop events from ALL our notebooks,
    // including the legacy single per-account notebook of the first version.
    // Dropped UIDs also identify stale artifacts from older sync versions
    // for selective cleanup. New replacement deletions are purged on save.
    QSet<QString> removedUids;
    QString legacyUid = QStringLiteral("proton-calendar-%1").arg(m_accountId);
    QString prefix = QStringLiteral("proton-calendar-%1-").arg(m_accountId);
    mKCal::Notebook::List nbs = storage->notebooks();
    mKCal::Notebook::Ptr legacyNotebook;
    for (const mKCal::Notebook::Ptr &nb : nbs) {
        if (!nb) continue;
        if (nb->uid() != legacyUid && !nb->uid().startsWith(prefix)) continue;
        if (nb->uid() == legacyUid) {
            // Notebook deletion is immediate: defer until replacement saved.
            legacyNotebook = nb;
            continue;
        }
        if (!storage->loadNotebookIncidences(nb->uid())) return false;
        KCalendarCore::Incidence::List existing = cal->incidences(nb->uid());
        int removed = 0;
        for (const KCalendarCore::Incidence::Ptr &inc : existing) {
            KCalendarCore::Event::Ptr ev = inc.dynamicCast<KCalendarCore::Event>();
            if (ev) {
                if (!cal->deleteEvent(ev)) return false;
                removedUids.insert(ev->uid());
                removed++;
            }
        }
        if (removed > 0) {
            proton_log(QStringLiteral("Removed %1 old events from %2").arg(removed).arg(nb->uid()));
        }
    }
    int saved = 0;
    QStringList syncedNotebooks;
    // Retired v1 notebook id is also purged below (its tombstones linger).
    syncedNotebooks << QStringLiteral("proton-calendar-%1").arg(m_accountId);
    auto rowRecurrenceId = [](const QJsonObject &o) {
        return o.value(QLatin1String("recurrence_id")).toVariant().toLongLong();
    };
    for (auto it = byCal.constBegin(); it != byCal.constEnd(); ++it) {
        QString nbUid = findOrCreateNotebook(cal, storage, it.key(), calNames.value(it.key()));
        if (nbUid.isEmpty()) return false;
        if (!syncedNotebooks.contains(nbUid)) syncedNotebooks << nbUid;
        if (!storage->loadNotebookIncidences(nbUid)) {
            proton_log(QStringLiteral("loadNotebookIncidences failed; import aborted"));
            return false;
        }
        // Pass 1: masters (no recurrence-id). Pass 2 decomposes exceptions
        // into master-EXDATE + standalone edited event (T15).
        for (int pass = 0; pass < 2; ++pass) {
        for (int idx : it.value()) {
            QJsonObject o = arr.at(idx).toObject();
        QString uid = o.value(QLatin1String("uid")).toString();
        QString summary = o.value(QLatin1String("summary")).toString();
        if (uid.isEmpty() && summary.isEmpty()) continue;
        qint64 recurrenceId = rowRecurrenceId(o);
        bool isException = recurrenceId > 0;
        if ((pass == 0) == isException) continue;
        QDateTime start, end;
        bool fullDay = false;
        eventTimes(o, start, end, fullDay);
        if (!isException) {
            KCalendarCore::Event::Ptr ev(new KCalendarCore::Event());
            fillEventFromJson(ev, o, uid, start, end, fullDay);
            ev->setUid(namespacedUid(uid));
            if (cal->addEvent(ev, nbUid)) {
                saved++;
            } else {
                proton_log(QStringLiteral("addEvent failed uid=") + uid.left(64));
                return false;
            }
            continue;
        }
        // Exception occurrence (T15): mkcal's exception machinery
        // (dissociate + same-UID save) never persisted the row — the
        // dissociated object isn't inserted by dissociate, and explicitly
        // added copies with recurrenceId are silently skipped at save.
        // Decompose instead, using only proven primitives: EXDATE the
        // original occurrence on the master + save the edited occurrence
        // as a plain event with a stable suffixed UID. Display result is
        // identical; no recurrenceId anywhere.
        QDateTime rid = utcFromUnix(recurrenceId);
        KCalendarCore::Event::Ptr master = cal->event(namespacedUid(uid));
        if (master && master->recursAt(rid)) {
            master->recurrence()->addExDateTime(rid);
        } else if (master) {
            proton_log(QStringLiteral("exception rid matches no occurrence, standalone only uid=") + uid.left(64));
        } else {
            proton_log(QStringLiteral("exception without master, standalone uid=") + uid.left(64));
        }
        KCalendarCore::Event::Ptr solo(new KCalendarCore::Event());
        QString soloUid = QStringLiteral("%1#%2").arg(uid, QString::number(recurrenceId));
        fillEventFromJson(solo, o, soloUid, start, end, fullDay);
        solo->setUid(namespacedUid(soloUid));
        if (cal->addEvent(solo, nbUid)) {
            saved++;
        } else {
            proton_log(QStringLiteral("addEvent exception failed uid=") + uid.left(64));
            return false;
        }
        continue;
        } // per-event rows of this Proton calendar
        } // pass 1 masters / pass 2 exceptions
    } // per Proton calendar notebook
    // These deletions are replacement artifacts, never user tombstones.
    // Remove them in the save itself, so a crash before the later purge
    // cannot leave a false delete for the next upsync. Previously persisted
    // user tombstones are still handled selectively below.
    if (!storage->save(mKCal::ExtendedStorage::PurgeDeleted)) {
        proton_log(QStringLiteral("mKCal storage save failed"));
        return false;
    }
    proton_log(QStringLiteral("Saved %1 calendar events to mkcal").arg(saved));
    if (legacyNotebook && storage->deleteNotebook(legacyNotebook)) {
        proton_log(QStringLiteral("Retired legacy notebook ") + legacyUid);
    }
    // Upsync bookkeeping (write-only today; consumed at wiring): per-row
    // Proton IDs, server-mtime anchors and lastModified snapshots so the
    // planner can map local inventory → server ops and detect dirt.
    persistUpsyncMaps(arr, cal);
    // Tombstone purge: selective for our notebooks (planner purgeable set
    // ∪ replacement-phase removals — the union covers both user deletes
    // whose server deletes uploaded OK and stale sync artifacts from older
    // versions). The retired v1 notebook keeps the legacy
    // unconditional purge (no live data, only lingering tombstones).
    // Fail-closed: m_purgeableUids is only populated from a `complete`
    // engine run whose uploads succeeded; any upload error aborts the
    // engine before we get here, so un-uploaded user tombstones survive
    // for the next cycle.
    {
        QSet<QString> purgeUids = m_purgeableUids + removedUids;
        QString legacyUid = QStringLiteral("proton-calendar-%1").arg(m_accountId);
        for (const QString &purgedNbUid : syncedNotebooks) {
            if (purgedNbUid == legacyUid) {
                KCalendarCore::Incidence::List deleted;
                if (storage->deletedIncidences(&deleted, QDateTime(), purgedNbUid) && !deleted.isEmpty()) {
                    if (storage->purgeDeletedIncidences(deleted, purgedNbUid)) {
                        proton_log(QStringLiteral("Purged %1 tombstones from %2").arg(deleted.size()).arg(purgedNbUid));
                    }
                }
                continue;
            }
            purgeListedTombstones(storage, QStringList() << purgedNbUid, purgeUids);
        }
    }
    return true;
}
// Upsync bookkeeping, written after every successful save (phase 4 data).
// Three JSON blobs under QSettings proton/sync-tokens/<accountId>:
// - proton_id_map: {stored mKCal UID: Proton row event ID} — tombstone
//   fallback when a deleted incidence lost its custom property.
// - proton_anchors: {Proton row ID: server LastEditTime} — planner anchors.
// - proton_last_modified: {stored mKCal UID: lastModified msecs} — dirt
//   baseline (missing entry = treat clean, so pre-feature rows never
//   mass-upload on the first wired sync).
void ProtonCalendarPlugin::persistUpsyncMaps(const QJsonArray &arr,
                                             const mKCal::ExtendedCalendar::Ptr &cal) {
    QVariantMap idMap, anchors, modified;
    for (int i = 0; i < arr.size(); ++i) {
        QJsonObject o = arr.at(i).toObject();
        QString uid = o.value(QLatin1String("uid")).toString();
        QString summary = o.value(QLatin1String("summary")).toString();
        if (uid.isEmpty() && summary.isEmpty()) continue; // same skip as save
        QString protonId = o.value(QLatin1String("id")).toString();
        if (protonId.isEmpty()) continue;
        qint64 recurrenceId = o.value(QLatin1String("recurrence_id")).toVariant().toLongLong();
        QString storedUid = recurrenceId > 0
            ? namespacedUid(QStringLiteral("%1#%2").arg(uid, QString::number(recurrenceId)))
            : namespacedUid(uid);
        idMap.insert(storedUid, protonId);
        bool mtimeOk = false;
        qint64 mtime = o.value(QLatin1String("mtime")).toVariant().toLongLong(&mtimeOk);
        if (mtimeOk) anchors.insert(protonId, mtime);
        KCalendarCore::Event::Ptr ev = cal->event(storedUid);
        if (ev && ev->lastModified().isValid()) {
            modified.insert(storedUid, ev->lastModified().toMSecsSinceEpoch());
        }
    }
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    settings.setValue(QStringLiteral("proton_id_map"),
                      QString::fromUtf8(QJsonDocument::fromVariant(idMap).toJson(QJsonDocument::Compact)));
    settings.setValue(QStringLiteral("proton_anchors"),
                      QString::fromUtf8(QJsonDocument::fromVariant(anchors).toJson(QJsonDocument::Compact)));
    settings.setValue(QStringLiteral("proton_last_modified"),
                      QString::fromUtf8(QJsonDocument::fromVariant(modified).toJson(QJsonDocument::Compact)));
    settings.endGroup();
}

// Selective tombstone purge for the wired upsync cycle: purge ONLY the
// listed UIDs, and only called after their server deletes uploaded OK.
// (Uncalled until wiring; the unconditional loop above stays until then.)
void ProtonCalendarPlugin::purgeListedTombstones(const mKCal::ExtendedStorage::Ptr &storage,
                                                 const QStringList &notebookUids,
                                                 const QSet<QString> &uids) {
    if (uids.isEmpty()) return;
    for (const QString &nbUid : notebookUids) {
        KCalendarCore::Incidence::List deleted;
        if (!storage->deletedIncidences(&deleted, QDateTime(), nbUid) || deleted.isEmpty()) {
            continue;
        }
        KCalendarCore::Incidence::List doomed;
        for (const KCalendarCore::Incidence::Ptr &inc : deleted) {
            if (inc && uids.contains(inc->uid())) doomed.append(inc);
        }
        if (!doomed.isEmpty() && storage->purgeDeletedIncidences(doomed, nbUid)) {
            proton_log(QStringLiteral("Purged %1 listed tombstones from %2").arg(doomed.size()).arg(nbUid));
        }
    }
}

// Local inventory for the upsync planner (wiring phase): one object per
// live incidence in our notebooks plus tombstones:
// {mkcal_uid, proton_id|null, deleted, modified, last_synced_mtime|null}
// (exact `upsync::LocalItem` contract). proton_id prefers the live
// X-PROTON-EVENT-ID custom property, falling back to the persisted id map
// (tombstones may shed custom props — verified live at wiring). dirty =
// lastModified differs from the stored snapshot (missing snapshot = clean,
// never mass-upload). last_synced_mtime comes from the persisted anchor
// map by proton_id.
QJsonArray ProtonCalendarPlugin::exportLocalInventory() {
    QJsonArray out;
    mKCal::ExtendedCalendar::Ptr cal(
        new mKCal::ExtendedCalendar(QTimeZone::systemTimeZone()));
    mKCal::ExtendedStorage::Ptr storage = mKCal::ExtendedCalendar::defaultStorage(cal);
    if (!storage->open()) {
        proton_log(QStringLiteral("exportLocalInventory: storage open failed"));
        return out;
    }
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    auto readMap = [&](const QString &key) {
        QVariantMap map;
        QJsonDocument doc = QJsonDocument::fromJson(
            settings.value(key).toString().toUtf8());
        if (doc.isObject()) map = doc.toVariant().toMap();
        return map;
    };
    QVariantMap idMap = readMap(QStringLiteral("proton_id_map"));
    QVariantMap anchors = readMap(QStringLiteral("proton_anchors"));
    QVariantMap lastMod = readMap(QStringLiteral("proton_last_modified"));
    QVariantMap pending = readMap(QStringLiteral("calendar_pending"));
    settings.endGroup();

    QString prefix = QStringLiteral("proton-calendar-%1-").arg(m_accountId);
    mKCal::Notebook::List nbs = storage->notebooks();
    for (const mKCal::Notebook::Ptr &nb : nbs) {
        if (!nb || !nb->uid().startsWith(prefix)) continue;
        // Proton calendar ID for create routing (no server row to read it
        // from); empty when the notebook UID has an unexpected shape.
        QString calId = nb->uid().mid(prefix.length());
        if (!storage->loadNotebookIncidences(nb->uid())) continue;
        KCalendarCore::Incidence::List existing = cal->incidences(nb->uid());
        QSet<QString> liveUids;
        for (const KCalendarCore::Incidence::Ptr &inc : existing) {
            if (inc) liveUids.insert(inc->uid());
        }
        for (const KCalendarCore::Incidence::Ptr &inc : existing) {
            KCalendarCore::Event::Ptr ev = inc.dynamicCast<KCalendarCore::Event>();
            if (!ev) continue;
            QJsonObject o;
            o.insert(QStringLiteral("mkcal_uid"), ev->uid());
            QString protonId = ev->customProperty("PROTON", "EVENT-ID");
            if (protonId.isEmpty()) protonId = idMap.value(ev->uid()).toString();
            o.insert(QStringLiteral("proton_id"),
                     protonId.isEmpty() ? QJsonValue() : QJsonValue(protonId));
            // Stable retry UID (if the previous cycle posted but never
            // confirmed): never-synced rows only, like the planner's
            // Create ops.
            if (protonId.isEmpty() && pending.contains(ev->uid())) {
                o.insert(QStringLiteral("pending_uid"), pending.value(ev->uid()).toString());
            }
            o.insert(QStringLiteral("deleted"), false);
            bool dirty = false;
            if (ev->lastModified().isValid() && lastMod.contains(ev->uid())) {
                dirty = lastMod.value(ev->uid()).toLongLong() != ev->lastModified().toMSecsSinceEpoch();
            }
            o.insert(QStringLiteral("modified"), dirty);
            // Contract key is last_synced_mtime (see upsync::LocalItem).
            if (!protonId.isEmpty() && anchors.contains(protonId)) {
                o.insert(QStringLiteral("last_synced_mtime"),
                         QJsonValue(anchors.value(protonId).toLongLong()));
            } else {
                o.insert(QStringLiteral("last_synced_mtime"), QJsonValue());
            }
            o.insert(QStringLiteral("calendar_id"),
                     calId.isEmpty() ? QJsonValue() : QJsonValue(calId));
            // Local field snapshot for rows the planner may upload (dirty
            // edits + never-synced creates). Clean rows omit it (None).
            if (!calId.isEmpty() && (dirty || protonId.isEmpty())
                && ev->dtStart().isValid() && ev->dtEnd().isValid()) {
                QJsonObject fields;
                fields.insert(QStringLiteral("summary"), ev->summary());
                fields.insert(QStringLiteral("description"), ev->description());
                fields.insert(QStringLiteral("location"), ev->location());
                fields.insert(QStringLiteral("start_unix"),
                              QJsonValue(ev->dtStart().toMSecsSinceEpoch() / 1000));
                fields.insert(QStringLiteral("end_unix"),
                              QJsonValue(ev->dtEnd().toMSecsSinceEpoch() / 1000));
                fields.insert(QStringLiteral("all_day"), ev->allDay());
                bool hasRecurrence = false;
                QString rrule;
                if (ev->recurrence() && ev->recurrence()->recurs()) {
                    KCalendarCore::RecurrenceRule::List rules = ev->recurrence()->rRules();
                    KCalendarCore::RecurrenceRule *first =
                        rules.isEmpty() ? nullptr : rules.first();
                    rrule = serializeRrule(first, &hasRecurrence);
                }
                // rrule/absent contract (see LocalFields): no rule at all
                // omits the key (keep on update); unserializable rule sends
                // explicit null (update keeps server rule, create defers).
                if (!hasRecurrence && rrule.isEmpty()) {
                    fields.insert(QStringLiteral("has_recurrence"), false);
                } else if (hasRecurrence && !rrule.isEmpty()) {
                    fields.insert(QStringLiteral("has_recurrence"), false);
                    fields.insert(QStringLiteral("rrule"), rrule);
                } else {
                    fields.insert(QStringLiteral("has_recurrence"), true);
                    fields.insert(QStringLiteral("rrule"), QJsonValue());
                }
                // Reminder state: current display alarms as row-shaped
                // {Trigger, Type:1} entries (explicit [] = user cleared all;
                // server-sent email alarms are merged back engine-side).
                // Only start-offset alarms map to Proton triggers.
                QJsonArray notifs;
                for (const KCalendarCore::Alarm::Ptr &alarm : ev->alarms()) {
                    if (!alarm || !alarm->hasStartOffset()) continue;
                    notifs.append(QJsonObject({
                        { QStringLiteral("Trigger"),
                          durationTrigger(alarm->startOffset().asSeconds()) },
                        { QStringLiteral("Type"), 1 },
                    }));
                }
                fields.insert(QStringLiteral("notifications"), notifs);
                // Event color (#RRGGBB or "" when unset; engine validates
                // against the palette, "" reverts to the calendar color).
                fields.insert(QStringLiteral("color"), ev->color());
                o.insert(QStringLiteral("fields"), fields);
            }
            out.append(o);
        }
        KCalendarCore::Incidence::List deleted;
        if (!storage->deletedIncidences(&deleted, QDateTime(), nb->uid())) continue;
        for (const KCalendarCore::Incidence::Ptr &inc : deleted) {
            if (!inc) continue;
            // Stale tombstone shadowing a live row (replacement artifact
            // from a crashed cycle): the live row wins, drop the tombstone
            // instead of uploading a spurious server delete.
            if (liveUids.contains(inc->uid())) continue;
            QJsonObject o;
            o.insert(QStringLiteral("mkcal_uid"), inc->uid());
            QString protonId = inc->customProperty("PROTON", "EVENT-ID");
            if (protonId.isEmpty()) protonId = idMap.value(inc->uid()).toString();
            o.insert(QStringLiteral("proton_id"),
                     protonId.isEmpty() ? QJsonValue() : QJsonValue(protonId));
            // Raw iCal UID for the out-of-window fallback (strip the
            // account namespace + any #rid exception suffix): lets the
            // engine UID-list rows the windowed listing missed.
            QString rawUid = inc->uid();
            if (rawUid.startsWith(prefix)) rawUid = rawUid.mid(prefix.length());
            int hash = rawUid.indexOf('#');
            if (hash >= 0) rawUid = rawUid.left(hash);
            o.insert(QStringLiteral("uid"),
                     rawUid.isEmpty() ? QJsonValue() : QJsonValue(rawUid));
            o.insert(QStringLiteral("deleted"), true);
            o.insert(QStringLiteral("modified"), false);
            if (!protonId.isEmpty() && anchors.contains(protonId)) {
                o.insert(QStringLiteral("last_synced_mtime"),
                         QJsonValue(anchors.value(protonId).toLongLong()));
            } else {
                o.insert(QStringLiteral("last_synced_mtime"), QJsonValue());
            }
            out.append(o);
        }
    }
    return out;
}

// Upsync anchor map ({Proton row ID: server LastEditTime}). Persisted
// wholesale after every `complete` run; empty input never clobbers (the
// engine getter returns null then, and this is only called with non-null).
void ProtonCalendarPlugin::persistUpsyncAnchors(const QString &anchorsJson) {
    if (anchorsJson.isEmpty()) {
        return;
    }
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    settings.setValue(QStringLiteral("proton_anchors"), anchorsJson);
    settings.endGroup();
}
QString ProtonCalendarPlugin::loadUpsyncAnchors() {
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    QString a = settings.value(QStringLiteral("proton_anchors")).toString();
    settings.endGroup();
    return a;
}
void ProtonCalendarPlugin::persistCalendarPending(const QString &pendingJson) {
    // Wholesale overwrite (never merge): empty clears confirmed/stale
    // entries. Cap logged length like the anchors line.
    if (!pendingJson.isEmpty()) {
        proton_log(QStringLiteral("Persisted calendar pending: %1").arg(pendingJson.left(500)));
    }
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    settings.setValue(QStringLiteral("calendar_pending"), pendingJson);
    settings.endGroup();
}
void ProtonCalendarPlugin::persistCalendarTokens(const QString &refreshToken, const QString &uid) {
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    settings.setValue(QStringLiteral("refresh_token"), refreshToken);
    settings.setValue(QStringLiteral("uid"), uid);
    settings.endGroup();
}
QPair<QString, QString> ProtonCalendarPlugin::loadPersistedCalendarTokens() {
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    QString rt = settings.value(QStringLiteral("refresh_token")).toString();
    QString uid = settings.value(QStringLiteral("uid")).toString();
    settings.endGroup();
    return qMakePair(rt, uid);
}
// Cached per-calendar reminder defaults ({calId: {part:[...], full:[...]}}).
// Written on fresh sessions (live settings non-empty) so restored sessions
// — whose live settings come back empty — resolve the same VALARMs.
void ProtonCalendarPlugin::persistCalendarDefaults(const QString &defaultsJson) {
    if (defaultsJson.isEmpty()) {
        return;
    }
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    settings.setValue(QStringLiteral("calendar_defaults"), defaultsJson);
    settings.endGroup();
    proton_log(QStringLiteral("Persisted calendar defaults for account ") + m_accountId);
}
QString ProtonCalendarPlugin::loadCalendarDefaults() {
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    QString d = settings.value(QStringLiteral("calendar_defaults")).toString();
    settings.endGroup();
    return d;
}
void ProtonCalendarPlugin::abortSync(Sync::SyncStatus aStatus) {
    Q_UNUSED(aStatus);
    if (m_calTimer) m_calTimer->stop();
}
bool ProtonCalendarPlugin::cleanUp() { return true; }
Buteo::SyncResults ProtonCalendarPlugin::getSyncResults() const { return Buteo::SyncResults(); }
void ProtonCalendarPlugin::connectivityStateChanged(Sync::ConnectivityType aType, bool aState) { Q_UNUSED(aType); Q_UNUSED(aState); }

Buteo::ClientPlugin *ProtonPluginLoader::createClientPlugin(const QString &aPluginName,
                                                            const Buteo::SyncProfile &aProfile,
                                                            Buteo::PluginCbInterface *aCbInterface)
{
    // Single libproton-client.so serves both contacts and calendar (same Sync Protocol "proton")
    // Distinguish by sync profile name (proton-carddav-* vs proton-caldav-*)
    QMap<QString, QString> keys = aProfile.allKeys();
    QStringList log;
    log << QStringLiteral("createClientPlugin: name=") + aProfile.name();
    for (auto it = keys.constBegin(); it != keys.constEnd(); ++it) {
        log << it.key() + QLatin1Char('=') + it.value();
    }
    proton_log(log.join(QStringLiteral(" | ")));
    if (aProfile.name().contains(QStringLiteral("caldav")) || aProfile.name().contains(QStringLiteral("calendar")) || aProfile.name().contains(QStringLiteral("Calendar"))) {
        return new ProtonCalendarPlugin(aPluginName, aProfile, aCbInterface);
    }
    return new ProtonContactsPlugin(aPluginName, aProfile, aCbInterface);
}
