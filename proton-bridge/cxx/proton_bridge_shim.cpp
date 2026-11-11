#include "proton_bridge_shim.h"
#include "proton_log.h"
#include "proton_settings.h"

#include <QBuffer>
#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDateTime>
#include <QImage>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QTimeZone>
#include <QUrl>

#include <QContactAddress>
#include <QContactAnniversary>
#include <QContactAvatar>
#include <QContactBirthday>
#include <QContactCollectionFilter>
#include <QContactDisplayLabel>
#include <QContactEmailAddress>
#include <QContactGender>
#include <QContactGuid>
#include <QContactName>
#include <QContactNickname>
#include <QContactNote>
#include <QContactOrganization>
#include <QContactPhoneNumber>
#include <QContactSyncTarget>
#include <QContactTimestamp>
#include <QContactUrl>

#include <notebook.h>
#include <KCalendarCore/Alarm>
#include <KCalendarCore/Attendee>
#include <KCalendarCore/Person>
#include <KCalendarCore/Recurrence>
#include <KCalendarCore/RecurrenceRule>

#include <Accounts/account.h>
#include <Accounts/account-service.h>
#include <Accounts/auth-data.h>
#include <Accounts/service.h>

using namespace Proton;
namespace QC = QtContacts;
namespace KC = KCalendarCore;

// ---- small helpers ----

static QJsonObject failure(const QString &error)
{
    return QJsonObject{{QStringLiteral("ok"), false}, {QStringLiteral("error"), error}};
}

static QJsonObject okResult(const QJsonValue &data)
{
    return QJsonObject{{QStringLiteral("ok"), true}, {QStringLiteral("data"), data}};
}

static void sendNotification(const QString &summary, const QString &body)
{
    QDBusMessage msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.freedesktop.Notifications"),
        QStringLiteral("/org/freedesktop/Notifications"),
        QStringLiteral("org.freedesktop.Notifications"),
        QStringLiteral("Notify"));
    msg.setArguments(QVariantList()
                     << QStringLiteral("proton-contacts") << uint(0)
                     << QStringLiteral("image://theme/icon-m-file-vcard")
                     << summary << body << QStringList() << QVariantMap() << int(10000));
    QDBusConnection::sessionBus().call(msg, QDBus::NoBlock);
}

static qint64 secs(const QDateTime &dt)
{
    return dt.toMSecsSinceEpoch() / 1000;
}

// Version-independent unix → UTC (fromTime_t + setTimeSpec shifted by the
// local offset on the device's Qt).
static QDateTime utcFromUnix(qint64 s)
{
    return QDateTime(QDate(1970, 1, 1), QTime(0, 0, 0), Qt::UTC).addSecs(s);
}

// {"utc": secs} | {"local": "yyyy-MM-ddTHH:mm:ss", "tz"?: IANA name}
static QDateTime toDateTime(const QJsonValue &value)
{
    const QJsonObject t = value.toObject();
    if (t.contains(QLatin1String("utc"))) {
        return utcFromUnix(t.value(QLatin1String("utc")).toVariant().toLongLong());
    }
    const QDateTime local = QDateTime::fromString(t.value(QLatin1String("local")).toString(), Qt::ISODate);
    const QString tz = t.value(QLatin1String("tz")).toString();
    if (!tz.isEmpty()) {
        QTimeZone zone(tz.toUtf8());
        if (zone.isValid()) {
            return QDateTime(local.date(), local.time(), zone);
        }
    }
    return local;
}

static QJsonArray namesOf(const QList<int> &values, const QList<QPair<int, QString>> &table)
{
    QJsonArray out;
    for (const auto &entry : table) {
        if (values.contains(entry.first)) out.append(entry.second);
    }
    return out;
}

static QList<int> valuesOf(const QJsonValue &names, const QList<QPair<int, QString>> &table)
{
    QList<int> out;
    for (const QJsonValue &name : names.toArray()) {
        for (const auto &entry : table) {
            if (entry.second == name.toString() && !out.contains(entry.first)) out << entry.first;
        }
    }
    return out;
}

static const QList<QPair<int, QString>> &contextTable()
{
    static const QList<QPair<int, QString>> table = {
        {QC::QContactDetail::ContextHome, QStringLiteral("home")},
        {QC::QContactDetail::ContextWork, QStringLiteral("work")},
    };
    return table;
}

static const QList<QPair<int, QString>> &subTypeTable()
{
    typedef QC::QContactPhoneNumber P;
    static const QList<QPair<int, QString>> table = {
        {P::SubTypeMobile, QStringLiteral("mobile")}, {P::SubTypeFax, QStringLiteral("fax")},
        {P::SubTypePager, QStringLiteral("pager")},   {P::SubTypeVoice, QStringLiteral("voice")},
        {P::SubTypeVideo, QStringLiteral("video")},   {P::SubTypeCar, QStringLiteral("car")},
    };
    return table;
}

// ---- plugin lifecycle ----

ProtonSyncPlugin::ProtonSyncPlugin(const QString &aPluginName,
                                   const Buteo::SyncProfile &aProfile,
                                   Buteo::PluginCbInterface *aCbInterface,
                                   bool calendar)
    : Buteo::ClientPlugin(aPluginName, aProfile, aCbInterface)
    , m_calendar(calendar)
{
    m_timer.setSingleShot(true);
    connect(&m_timer, &QTimer::timeout, this, &ProtonSyncPlugin::poll);
    proton_log(QStringLiteral("ProtonSyncPlugin constructed: %1 profile=%2 kind=%3")
               .arg(aPluginName, getProfileName(),
                    m_calendar ? QStringLiteral("calendar") : QStringLiteral("contacts")));
}

ProtonSyncPlugin::~ProtonSyncPlugin()
{
    uninit();
}

bool ProtonSyncPlugin::init()
{
    m_accountId = iProfile.key(QStringLiteral("accountid"));
    if (m_accountId.isEmpty()) {
        QRegularExpressionMatch match = QRegularExpression(QStringLiteral("-(\\d+)$")).match(getProfileName());
        if (match.hasMatch()) m_accountId = match.captured(1);
    }
    if (m_accountId.isEmpty()) m_accountId = iProfile.key(QStringLiteral("account_id"));
    if (m_accountId.isEmpty()) {
        proton_log(QStringLiteral("ERROR: Cannot determine accountid for ") + getProfileName());
        return false;
    }
    proton_log(QStringLiteral("init() profile=%1 accountid=%2").arg(getProfileName(), m_accountId));
    m_accountManager = new Accounts::Manager(this);
    return requestCredentials();
}

bool ProtonSyncPlugin::uninit()
{
    m_timer.stop();
    if (m_sync) {
        proton_sync_free(m_sync);
        m_sync = nullptr;
    }
    m_dumpedContacts.clear();
    m_dumpedEvents.clear();
    m_cal.clear();
    m_storage.clear();
    delete m_contacts;
    m_contacts = nullptr;
    return true;
}

// The run starts once SignOn answers (onSignOnResponse).
bool ProtonSyncPlugin::startSync() { return true; }

void ProtonSyncPlugin::abortSync(Sync::SyncStatus aStatus)
{
    Q_UNUSED(aStatus);
    m_timer.stop();
}

bool ProtonSyncPlugin::cleanUp() { return true; }

Buteo::SyncResults ProtonSyncPlugin::getSyncResults() const { return Buteo::SyncResults(); }

void ProtonSyncPlugin::connectivityStateChanged(Sync::ConnectivityType aType, bool aState)
{
    Q_UNUSED(aType);
    Q_UNUSED(aState);
}

// ---- credentials ----

bool ProtonSyncPlugin::requestCredentials()
{
    Accounts::Account *account = Accounts::Account::fromId(
        m_accountManager, static_cast<Accounts::AccountId>(m_accountId.toUInt()), this);
    if (!account) {
        proton_log(QStringLiteral("ERROR: Unable to load account ") + m_accountId);
        return false;
    }
    // The shared identity lives on the contacts service.
    Accounts::Service service = m_accountManager->service(
        m_calendar ? QStringLiteral("proton-caldav") : QStringLiteral("proton-carddav"));
    if (!service.isValid()) service = m_accountManager->service(QStringLiteral("proton-carddav"));
    if (!service.isValid()) {
        proton_log(QStringLiteral("ERROR: Unable to find Proton account service"));
        return false;
    }
    account->selectService(service);
    Accounts::AuthData authData = (new Accounts::AccountService(account, service, this))->authData();
    quint32 credentialsId = authData.credentialsId();
    if (credentialsId == 0) {
        // Some creation flows store CredentialsId as int32, which the
        // uint32 getter cannot read: fall back to the generic read and heal
        // the stored type.
        QVariant raw = account->value(QStringLiteral("CredentialsId"));
        if (raw.isValid() && raw.toUInt() > 0) {
            credentialsId = raw.toUInt();
            proton_log(QStringLiteral("Healing CredentialsId to ") + QString::number(credentialsId));
            account->setCredentialsId(credentialsId);
            account->sync();
        }
    }
    if (credentialsId == 0) {
        // Last resort: the provider-wide default credentials.
        account->selectService(Accounts::Service());
        credentialsId = account->credentialsId();
        account->selectService(service);
    }
    m_identity = SignOn::Identity::existingIdentity(credentialsId, this);
    if (!m_identity) {
        proton_log(QStringLiteral("ERROR: No SignOn identity for id=") + QString::number(credentialsId));
        return false;
    }
    m_authSession = m_identity->createSession(authData.method());
    if (!m_authSession) {
        proton_log(QStringLiteral("ERROR: Unable to create SignOn auth session"));
        return false;
    }
    connect(m_authSession, &SignOn::AuthSession::response, this, &ProtonSyncPlugin::onSignOnResponse);
    connect(m_authSession, &SignOn::AuthSession::error, this, &ProtonSyncPlugin::onSignOnError);
    // Never prompt from a sync: expired credentials surface as an
    // authentication failure and the user updates them in Settings.
    SignOn::SessionData sessionData;
    sessionData.setUiPolicy(SignOn::NoUserInteractionPolicy);
    m_authSession->process(sessionData, authData.mechanism());
    proton_log(QStringLiteral("SignOn session started (credentials %1, method %2)")
               .arg(credentialsId).arg(authData.method()));
    return true;
}

void ProtonSyncPlugin::onSignOnResponse(const SignOn::SessionData &data)
{
    QJsonObject credentials;
    for (const QString &name : data.propertyNames()) {
        credentials.insert(name, QJsonValue::fromVariant(data.getProperty(name)));
    }
    if (m_sync) proton_sync_free(m_sync);
    m_sync = proton_sync_new(m_calendar ? "calendar" : "contacts", m_accountId.toUtf8().constData());
    if (!m_sync) {
        emit error(getProfileName(), QStringLiteral("Failed to create sync session"),
                   Buteo::SyncResults::INTERNAL_ERROR);
        return;
    }
    drive(QJsonObject{{QStringLiteral("begin"),
                       QJsonObject{{QStringLiteral("credentials"), credentials},
                                   {QStringLiteral("settings"), proton_settings_load()}}}});
}

void ProtonSyncPlugin::onSignOnError(const SignOn::Error &signOnError)
{
    proton_log(QStringLiteral("SignOn error type=%1 msg=%2").arg(signOnError.type()).arg(signOnError.message()));
    emit error(getProfileName(), QStringLiteral("Authentication failed: ") + signOnError.message(),
               Buteo::SyncResults::AUTHENTICATION_FAILURE);
}

// ---- driver ----

void ProtonSyncPlugin::poll()
{
    drive(QJsonObject{{QStringLiteral("poll"), QJsonObject()}});
}

void ProtonSyncPlugin::drive(QJsonObject input)
{
    while (m_sync) {
        char *raw = proton_sync_step(m_sync, QJsonDocument(input).toJson(QJsonDocument::Compact).constData());
        const QJsonObject out = QJsonDocument::fromJson(QByteArray(raw)).object();
        proton_string_free(raw);

        proton_settings_apply(out.value(QLatin1String("settings")).toObject());
        for (const QJsonValue &line : out.value(QLatin1String("log")).toArray()) {
            proton_log(line.toString());
        }
        for (const QJsonValue &n : out.value(QLatin1String("notices")).toArray()) {
            const QJsonObject notice = n.toObject();
            sendNotification(notice.value(QLatin1String("summary")).toString(),
                             notice.value(QLatin1String("body")).toString());
        }
        if (out.contains(QLatin1String("result"))) {
            finish(out.value(QLatin1String("result")).toObject());
            return;
        }
        const QJsonObject request = out.value(QLatin1String("request")).toObject();
        const QString kind = request.value(QLatin1String("kind")).toString();
        if (kind == QLatin1String("poll")) {
            m_timer.start(request.value(QLatin1String("after_ms")).toInt(500));
            return;
        } else if (kind == QLatin1String("local")) {
            input = QJsonObject{{QStringLiteral("local"), m_calendar ? dumpCalendar() : dumpContacts()}};
        } else if (kind == QLatin1String("avatars")) {
            // Avatar files → data URIs for the vCard PHOTO line (512px
            // bounding box, JPEG q85); "" when unreadable.
            QJsonObject converted;
            for (const QJsonValue &source : request.value(QLatin1String("sources")).toArray()) {
                const QString path = QUrl(source.toString()).toLocalFile();
                QImage image(path.isEmpty() ? source.toString() : path);
                QString uri;
                if (!image.isNull()) {
                    if (qMax(image.width(), image.height()) > 512) {
                        image = image.scaled(512, 512, Qt::KeepAspectRatio, Qt::SmoothTransformation);
                    }
                    QByteArray bytes;
                    QBuffer buffer(&bytes);
                    if (buffer.open(QIODevice::WriteOnly) && image.save(&buffer, "JPEG", 85)) {
                        uri = QStringLiteral("data:image/jpeg;base64,") + QString::fromLatin1(bytes.toBase64());
                    }
                }
                converted.insert(source.toString(), uri);
            }
            input = QJsonObject{{QStringLiteral("avatars"), QJsonObject{{QStringLiteral("data"), converted}}}};
        } else if (kind == QLatin1String("write")) {
            const QJsonObject plan = request.value(QLatin1String("plan")).toObject();
            input = QJsonObject{{QStringLiteral("written"), m_calendar ? writeCalendar(plan) : writeContacts(plan)}};
        } else {
            proton_log(QStringLiteral("Unknown request from sync session: ") + kind);
            emit error(getProfileName(), QStringLiteral("Internal error"), Buteo::SyncResults::INTERNAL_ERROR);
            return;
        }
    }
}

void ProtonSyncPlugin::finish(const QJsonObject &result)
{
    m_timer.stop();
    // Store handles are only valid within one dump/write exchange.
    m_dumpedContacts.clear();
    m_dumpedEvents.clear();
    m_cal.clear();
    m_storage.clear();
    const QString message = result.value(QLatin1String("message")).toString();
    if (result.value(QLatin1String("ok")).toBool()) {
        emit success(getProfileName(), message);
    } else {
        emit error(getProfileName(), message,
                   result.value(QLatin1String("auth_failure")).toBool()
                       ? Buteo::SyncResults::AUTHENTICATION_FAILURE
                       : Buteo::SyncResults::INTERNAL_ERROR);
    }
}

// ---- contacts store ----

QC::QContactCollection ProtonSyncPlugin::findOrCreateCollection()
{
    if (!m_contacts) {
        m_contacts = new QC::QContactManager(QStringLiteral("org.nemomobile.contacts.sqlite"));
    }
    const QString remoteUid = QStringLiteral("proton-contacts-%1").arg(m_accountId);
    for (const QC::QContactCollection &col : m_contacts->collections()) {
        QVariantMap extended = col.metaData(QC::QContactCollection::KeyExtended).toMap();
        if (extended.value(QStringLiteral("remote_uid")).toString() == remoteUid) return col;
    }
    QC::QContactCollection collection;
    collection.setMetaData(QC::QContactCollection::KeyName, QStringLiteral("Proton Contacts (%1)").arg(m_accountId));
    QVariantMap extended;
    extended.insert(QStringLiteral("remote_uid"), remoteUid);
    extended.insert(QStringLiteral("account_id"), m_accountId);
    collection.setMetaData(QC::QContactCollection::KeyExtended, extended);
    if (!m_contacts->saveCollection(&collection)) {
        proton_log(QStringLiteral("Failed to create contacts collection, error=%1").arg(int(m_contacts->error())));
        return QC::QContactCollection();
    }
    proton_log(QStringLiteral("Created contacts collection ") + remoteUid);
    return collection;
}

static QJsonObject contactToJson(const QC::QContact &c)
{
    QJsonObject o;
    o.insert(QStringLiteral("id"), c.id().toString());
    o.insert(QStringLiteral("guid"), c.detail<QC::QContactGuid>().guid());
    const QDateTime modified = c.detail<QC::QContactTimestamp>().lastModified();
    if (modified.isValid()) o.insert(QStringLiteral("last_modified"), modified.toMSecsSinceEpoch());
    const QC::QContactName name = c.detail<QC::QContactName>();
    o.insert(QStringLiteral("first_name"), name.firstName());
    o.insert(QStringLiteral("last_name"), name.lastName());
    o.insert(QStringLiteral("display_label"), c.detail<QC::QContactDisplayLabel>().label());
    QJsonArray emails;
    for (const QC::QContactEmailAddress &e : c.details<QC::QContactEmailAddress>()) {
        emails.append(QJsonObject{{QStringLiteral("email"), e.emailAddress()},
                                  {QStringLiteral("contexts"), namesOf(e.contexts(), contextTable())}});
    }
    o.insert(QStringLiteral("emails"), emails);
    QJsonArray phones;
    for (const QC::QContactPhoneNumber &p : c.details<QC::QContactPhoneNumber>()) {
        phones.append(QJsonObject{{QStringLiteral("number"), p.number()},
                                  {QStringLiteral("sub_types"), namesOf(p.subTypes(), subTypeTable())},
                                  {QStringLiteral("contexts"), namesOf(p.contexts(), contextTable())}});
    }
    o.insert(QStringLiteral("phones"), phones);
    QJsonArray addresses;
    for (const QC::QContactAddress &a : c.details<QC::QContactAddress>()) {
        addresses.append(QJsonObject{{QStringLiteral("street"), a.street()},
                                     {QStringLiteral("locality"), a.locality()},
                                     {QStringLiteral("region"), a.region()},
                                     {QStringLiteral("postcode"), a.postcode()},
                                     {QStringLiteral("country"), a.country()},
                                     {QStringLiteral("contexts"), namesOf(a.contexts(), contextTable())}});
    }
    o.insert(QStringLiteral("addresses"), addresses);
    const QC::QContactOrganization org = c.detail<QC::QContactOrganization>();
    o.insert(QStringLiteral("organization"), QJsonObject{{QStringLiteral("name"), org.name()},
                                                         {QStringLiteral("title"), org.title()},
                                                         {QStringLiteral("role"), org.role()}});
    QJsonArray notes;
    for (const QC::QContactNote &n : c.details<QC::QContactNote>()) notes.append(n.note());
    o.insert(QStringLiteral("notes"), notes);
    const QDate birthday = c.detail<QC::QContactBirthday>().date();
    o.insert(QStringLiteral("birthday"), birthday.isValid() ? birthday.toString(Qt::ISODate) : QString());
    const QDate anniversary = c.detail<QC::QContactAnniversary>().originalDate();
    o.insert(QStringLiteral("anniversary"), anniversary.isValid() ? anniversary.toString(Qt::ISODate) : QString());
    o.insert(QStringLiteral("nickname"), c.detail<QC::QContactNickname>().nickname());
    o.insert(QStringLiteral("url"), c.detail<QC::QContactUrl>().url());
    const auto gender = c.detail<QC::QContactGender>().gender();
    o.insert(QStringLiteral("gender"), gender == QC::QContactGender::GenderMale ? QStringLiteral("male")
                                       : gender == QC::QContactGender::GenderFemale ? QStringLiteral("female")
                                                                                    : QString());
    QJsonArray avatars;
    for (const QC::QContactAvatar &a : c.details<QC::QContactAvatar>()) avatars.append(a.imageUrl().toString());
    o.insert(QStringLiteral("avatars"), avatars);
    return o;
}

static QC::QContact contactFromSpec(const QJsonObject &s, const QC::QContactCollectionId &collectionId)
{
    auto text = [&s](const char *key) { return s.value(QLatin1String(key)).toString(); };
    QC::QContact contact;
    contact.setCollectionId(collectionId);
    QC::QContactSyncTarget target;
    target.setSyncTarget(QStringLiteral("proton"));
    contact.saveDetail(&target);
    if (!text("first_name").isEmpty() || !text("last_name").isEmpty()) {
        QC::QContactName name;
        name.setFirstName(text("first_name"));
        name.setLastName(text("last_name"));
        contact.saveDetail(&name);
    }
    if (!text("display_label").isEmpty()) {
        QC::QContactDisplayLabel label;
        label.setLabel(text("display_label"));
        contact.saveDetail(&label);
    }
    if (!text("guid").isEmpty()) {
        QC::QContactGuid guid;
        guid.setGuid(text("guid"));
        contact.saveDetail(&guid);
    }
    for (const QJsonValue &v : s.value(QLatin1String("emails")).toArray()) {
        const QJsonObject e = v.toObject();
        QC::QContactEmailAddress email;
        email.setEmailAddress(e.value(QLatin1String("email")).toString());
        const QList<int> contexts = valuesOf(e.value(QLatin1String("contexts")), contextTable());
        if (!contexts.isEmpty()) email.setContexts(contexts);
        contact.saveDetail(&email);
    }
    for (const QJsonValue &v : s.value(QLatin1String("phones")).toArray()) {
        const QJsonObject p = v.toObject();
        QC::QContactPhoneNumber phone;
        phone.setNumber(p.value(QLatin1String("number")).toString());
        const QList<int> subTypes = valuesOf(p.value(QLatin1String("sub_types")), subTypeTable());
        const QList<int> contexts = valuesOf(p.value(QLatin1String("contexts")), contextTable());
        if (!subTypes.isEmpty()) phone.setSubTypes(subTypes);
        if (!contexts.isEmpty()) phone.setContexts(contexts);
        contact.saveDetail(&phone);
    }
    for (const QJsonValue &v : s.value(QLatin1String("addresses")).toArray()) {
        const QJsonObject a = v.toObject();
        QC::QContactAddress address;
        address.setStreet(a.value(QLatin1String("street")).toString());
        address.setLocality(a.value(QLatin1String("locality")).toString());
        address.setRegion(a.value(QLatin1String("region")).toString());
        address.setPostcode(a.value(QLatin1String("postcode")).toString());
        address.setCountry(a.value(QLatin1String("country")).toString());
        const QList<int> contexts = valuesOf(a.value(QLatin1String("contexts")), contextTable());
        if (!contexts.isEmpty()) address.setContexts(contexts);
        contact.saveDetail(&address);
    }
    if (s.value(QLatin1String("organization")).isObject()) {
        const QJsonObject o = s.value(QLatin1String("organization")).toObject();
        QC::QContactOrganization org;
        if (!o.value(QLatin1String("name")).toString().isEmpty()) org.setName(o.value(QLatin1String("name")).toString());
        if (!o.value(QLatin1String("title")).toString().isEmpty()) org.setTitle(o.value(QLatin1String("title")).toString());
        if (!o.value(QLatin1String("role")).toString().isEmpty()) org.setRole(o.value(QLatin1String("role")).toString());
        contact.saveDetail(&org);
    }
    if (!text("note").isEmpty()) {
        QC::QContactNote note;
        note.setNote(text("note"));
        contact.saveDetail(&note);
    }
    const QDate birthday = QDate::fromString(text("birthday"), Qt::ISODate);
    if (birthday.isValid()) {
        QC::QContactBirthday detail;
        detail.setDate(birthday);
        contact.saveDetail(&detail);
    }
    const QDate anniversary = QDate::fromString(text("anniversary"), Qt::ISODate);
    if (anniversary.isValid()) {
        QC::QContactAnniversary detail;
        detail.setOriginalDate(anniversary);
        contact.saveDetail(&detail);
    }
    if (!text("nickname").isEmpty()) {
        QC::QContactNickname detail;
        detail.setNickname(text("nickname"));
        contact.saveDetail(&detail);
    }
    if (!text("url").isEmpty()) {
        QC::QContactUrl detail;
        detail.setUrl(text("url"));
        contact.saveDetail(&detail);
    }
    if (!text("gender").isEmpty()) {
        QC::QContactGender detail;
        detail.setGender(text("gender") == QLatin1String("female") ? QC::QContactGender::GenderFemale
                                                                  : QC::QContactGender::GenderMale);
        contact.saveDetail(&detail);
    }
    const QString avatar = text("avatar");
    if (!avatar.isEmpty()) {
        QC::QContactAvatar detail;
        detail.setImageUrl(avatar.startsWith(QLatin1String("data:")) ? QUrl(avatar)
                                                                     : QUrl::fromEncoded(avatar.toUtf8()));
        contact.saveDetail(&detail);
    }
    return contact;
}

QJsonObject ProtonSyncPlugin::dumpContacts()
{
    m_dumpedContacts.clear();
    const QC::QContactCollection collection = findOrCreateCollection();
    if (collection.id().isNull()) return failure(QStringLiteral("contacts collection unavailable"));
    m_collectionId = collection.id();
    QC::QContactCollectionFilter filter;
    filter.setCollectionId(m_collectionId);
    m_dumpedContacts = m_contacts->contacts(filter);
    if (m_contacts->error() != QC::QContactManager::NoError) {
        m_dumpedContacts.clear();
        return failure(QStringLiteral("contacts read error %1").arg(int(m_contacts->error())));
    }
    QJsonArray rows;
    for (const QC::QContact &c : m_dumpedContacts) rows.append(contactToJson(c));
    return okResult(rows);
}

// Plan: {save: [{ref|null, contact}], remove: [ref]}. Saves first, removals
// after, so a failed save leaves every local row in place.
QJsonObject ProtonSyncPlugin::writeContacts(const QJsonObject &plan)
{
    auto dumped = [this](const QJsonValue &ref, bool *ok) {
        const int index = ref.toInt(-1);
        *ok = index >= 0 && index < m_dumpedContacts.size();
        return *ok ? m_dumpedContacts.at(index).id() : QC::QContactId();
    };
    QList<QC::QContact> toSave;
    for (const QJsonValue &v : plan.value(QLatin1String("save")).toArray()) {
        const QJsonObject save = v.toObject();
        QC::QContact contact = contactFromSpec(save.value(QLatin1String("contact")).toObject(), m_collectionId);
        if (!save.value(QLatin1String("ref")).isNull()) {
            bool ok = false;
            contact.setId(dumped(save.value(QLatin1String("ref")), &ok));
            if (!ok) return failure(QStringLiteral("save refers to an unknown contact"));
        }
        toSave << contact;
    }
    if (!toSave.isEmpty()) {
        QMap<int, QC::QContactManager::Error> errors;
        if (!m_contacts->saveContacts(&toSave, &errors)) {
            QStringList detail;
            for (auto it = errors.constBegin(); it != errors.constEnd(); ++it) {
                detail << QStringLiteral("%1:%2").arg(it.key()).arg(int(it.value()));
            }
            return failure(QStringLiteral("saveContacts error=%1 rows=%2")
                           .arg(int(m_contacts->error())).arg(detail.join(QLatin1Char(','))));
        }
        QCoreApplication::processEvents();
    }
    QList<QC::QContactId> toRemove;
    for (const QJsonValue &ref : plan.value(QLatin1String("remove")).toArray()) {
        bool ok = false;
        const QC::QContactId id = dumped(ref, &ok);
        if (ok) toRemove << id;
    }
    if (!toRemove.isEmpty()) {
        QMap<int, QC::QContactManager::Error> errors;
        if (!m_contacts->removeContacts(toRemove, &errors)) {
            // Stale rows only: the next cycle retries.
            proton_log(QStringLiteral("Failed to remove %1 contacts, error=%2")
                       .arg(toRemove.size()).arg(int(m_contacts->error())));
        }
    }
    // Stored id, timestamp and last avatar as re-read from storage.
    QJsonArray saved;
    for (const QC::QContact &c : toSave) {
        QJsonObject row{{QStringLiteral("id"), c.id().isNull() ? QString() : c.id().toString()}};
        const QC::QContact fresh = m_contacts->contact(c.id());
        if (!c.id().isNull() && m_contacts->error() == QC::QContactManager::NoError) {
            const QDateTime modified = fresh.detail<QC::QContactTimestamp>().lastModified();
            if (modified.isValid()) row.insert(QStringLiteral("last_modified"), modified.toMSecsSinceEpoch());
            const QList<QC::QContactAvatar> avatars = fresh.details<QC::QContactAvatar>();
            if (!avatars.isEmpty()) row.insert(QStringLiteral("avatar"), avatars.last().imageUrl().toString());
        }
        saved.append(row);
    }
    return okResult(QJsonObject{{QStringLiteral("saved"), saved}});
}

// ---- calendar store ----

static QJsonArray intArray(const QList<int> &values)
{
    QJsonArray out;
    for (int v : values) out.append(v);
    return out;
}

static QList<int> intList(const QJsonValue &value)
{
    QList<int> out;
    for (const QJsonValue &v : value.toArray()) out << v.toInt();
    return out;
}

static QJsonObject ruleToJson(const KC::RecurrenceRule *rule)
{
    QString freq;
    switch (rule->recurrenceType()) {
    case KC::RecurrenceRule::rNone: freq = QStringLiteral("NONE"); break;
    case KC::RecurrenceRule::rDaily: freq = QStringLiteral("DAILY"); break;
    case KC::RecurrenceRule::rWeekly: freq = QStringLiteral("WEEKLY"); break;
    case KC::RecurrenceRule::rMonthly: freq = QStringLiteral("MONTHLY"); break;
    case KC::RecurrenceRule::rYearly: freq = QStringLiteral("YEARLY"); break;
    default: freq = QStringLiteral("SUBDAILY"); break;
    }
    QJsonArray byDay;
    for (const KC::RecurrenceRule::WDayPos &wp : rule->byDays()) {
        byDay.append(QJsonArray{int(wp.pos()), int(wp.day())});
    }
    QJsonObject o{{QStringLiteral("freq"), freq},
                  {QStringLiteral("interval"), int(rule->frequency())},
                  {QStringLiteral("count"), rule->duration() > 0 ? rule->duration() : 0},
                  {QStringLiteral("by_day"), byDay},
                  {QStringLiteral("by_month_day"), intArray(rule->byMonthDays())},
                  {QStringLiteral("by_month"), intArray(rule->byMonths())},
                  {QStringLiteral("by_set_pos"), intArray(rule->bySetPos())},
                  {QStringLiteral("wkst"), int(rule->weekStart())},
                  {QStringLiteral("unsupported_parts"),
                   !rule->byHours().isEmpty() || !rule->byMinutes().isEmpty() || !rule->bySeconds().isEmpty()
                       || !rule->byYearDays().isEmpty() || !rule->byWeekNumbers().isEmpty()}};
    if (rule->endDt().isValid()) o.insert(QStringLiteral("until"), secs(rule->endDt().toUTC()));
    return o;
}

static QJsonObject eventToJson(const KC::Event::Ptr &ev, const QString &notebook, bool deleted)
{
    QJsonObject o{{QStringLiteral("notebook"), notebook},
                  {QStringLiteral("uid"), ev->uid()},
                  {QStringLiteral("deleted"), deleted},
                  {QStringLiteral("event_id"), ev->customProperty("PROTON", "EVENT-ID")},
                  {QStringLiteral("ical_uid"), ev->customProperty("PROTON", "ICAL-UID")},
                  {QStringLiteral("summary"), ev->summary()},
                  {QStringLiteral("description"), ev->description()},
                  {QStringLiteral("location"), ev->location()},
                  {QStringLiteral("all_day"), ev->allDay()},
                  {QStringLiteral("color"), ev->color()}};
    if (ev->hasRecurrenceId()) o.insert(QStringLiteral("recurrence_id"), secs(ev->recurrenceId()));
    if (ev->lastModified().isValid()) o.insert(QStringLiteral("last_modified"), ev->lastModified().toMSecsSinceEpoch());
    if (ev->dtStart().isValid()) o.insert(QStringLiteral("start"), secs(ev->dtStart()));
    if (ev->dtEnd().isValid()) o.insert(QStringLiteral("end"), secs(ev->dtEnd()));
    const bool recurs = ev->recurrence() && ev->recurrence()->recurs();
    o.insert(QStringLiteral("recurs"), recurs);
    if (recurs && !ev->recurrence()->rRules().isEmpty()) {
        o.insert(QStringLiteral("rule"), ruleToJson(ev->recurrence()->rRules().first()));
    }
    QJsonArray alarms;
    for (const KC::Alarm::Ptr &alarm : ev->alarms()) {
        if (alarm && alarm->hasStartOffset()) alarms.append(qint64(alarm->startOffset().asSeconds()));
    }
    o.insert(QStringLiteral("alarms"), alarms);
    return o;
}

static KC::Attendee::PartStat partStat(const QString &s)
{
    static const QMap<QString, KC::Attendee::PartStat> map = {
        {QStringLiteral("ACCEPTED"), KC::Attendee::Accepted},   {QStringLiteral("DECLINED"), KC::Attendee::Declined},
        {QStringLiteral("TENTATIVE"), KC::Attendee::Tentative}, {QStringLiteral("DELEGATED"), KC::Attendee::Delegated},
        {QStringLiteral("COMPLETED"), KC::Attendee::Completed}, {QStringLiteral("IN-PROCESS"), KC::Attendee::InProcess},
        {QStringLiteral("NEEDS-ACTION"), KC::Attendee::NeedsAction},
    };
    return map.value(s, KC::Attendee::None);
}

static KC::Attendee::Role attendeeRole(const QString &s)
{
    static const QMap<QString, KC::Attendee::Role> map = {
        {QStringLiteral("CHAIR"), KC::Attendee::Chair},
        {QStringLiteral("OPT-PARTICIPANT"), KC::Attendee::OptParticipant},
        {QStringLiteral("NON-PARTICIPANT"), KC::Attendee::NonParticipant},
    };
    return map.value(s, KC::Attendee::ReqParticipant);
}

static KC::Event::Ptr eventFromSpec(const QJsonObject &s)
{
    auto text = [&s](const char *key) { return s.value(QLatin1String(key)).toString(); };
    KC::Event::Ptr ev(new KC::Event());
    ev->setUid(text("uid"));
    const QJsonObject props = s.value(QLatin1String("properties")).toObject();
    for (auto it = props.constBegin(); it != props.constEnd(); ++it) {
        ev->setCustomProperty("PROTON", it.key().toUtf8(), it.value().toString());
    }
    ev->setSummary(text("summary"));
    ev->setDescription(text("description"));
    ev->setLocation(text("location"));
    ev->setAllDay(s.value(QLatin1String("all_day")).toBool());
    const QDateTime start = toDateTime(s.value(QLatin1String("start")));
    ev->setDtStart(start);
    ev->setDtEnd(toDateTime(s.value(QLatin1String("end"))));
    if (s.value(QLatin1String("rrule")).isObject()) {
        const QJsonObject r = s.value(QLatin1String("rrule")).toObject();
        static const QMap<QString, KC::RecurrenceRule::PeriodType> periods = {
            {QStringLiteral("DAILY"), KC::RecurrenceRule::rDaily},
            {QStringLiteral("WEEKLY"), KC::RecurrenceRule::rWeekly},
            {QStringLiteral("MONTHLY"), KC::RecurrenceRule::rMonthly},
            {QStringLiteral("YEARLY"), KC::RecurrenceRule::rYearly},
            {QStringLiteral("HOURLY"), KC::RecurrenceRule::rHourly},
            {QStringLiteral("MINUTELY"), KC::RecurrenceRule::rMinutely},
            {QStringLiteral("SECONDLY"), KC::RecurrenceRule::rSecondly},
        };
        KC::RecurrenceRule *rule = new KC::RecurrenceRule();
        rule->setRecurrenceType(periods.value(r.value(QLatin1String("freq")).toString(), KC::RecurrenceRule::rDaily));
        rule->setFrequency(r.value(QLatin1String("interval")).toInt(1));
        rule->setStartDt(start);
        rule->setRRule(r.value(QLatin1String("text")).toString());
        QList<KC::RecurrenceRule::WDayPos> byDays;
        for (const QJsonValue &v : r.value(QLatin1String("by_day")).toArray()) {
            byDays << KC::RecurrenceRule::WDayPos(v.toArray().at(0).toInt(), short(v.toArray().at(1).toInt()));
        }
        if (!byDays.isEmpty()) rule->setByDays(byDays);
        if (!intList(r.value(QLatin1String("by_month_day"))).isEmpty()) rule->setByMonthDays(intList(r.value(QLatin1String("by_month_day"))));
        if (!intList(r.value(QLatin1String("by_month"))).isEmpty()) rule->setByMonths(intList(r.value(QLatin1String("by_month"))));
        if (!intList(r.value(QLatin1String("by_year_day"))).isEmpty()) rule->setByYearDays(intList(r.value(QLatin1String("by_year_day"))));
        if (!intList(r.value(QLatin1String("by_week_no"))).isEmpty()) rule->setByWeekNumbers(intList(r.value(QLatin1String("by_week_no"))));
        if (!intList(r.value(QLatin1String("by_set_pos"))).isEmpty()) rule->setBySetPos(intList(r.value(QLatin1String("by_set_pos"))));
        if (r.contains(QLatin1String("wkst"))) rule->setWeekStart(short(r.value(QLatin1String("wkst")).toInt()));
        if (r.contains(QLatin1String("count"))) {
            rule->setDuration(r.value(QLatin1String("count")).toInt());
        } else if (r.contains(QLatin1String("until"))) {
            rule->setEndDt(toDateTime(r.value(QLatin1String("until"))));
        }
        ev->recurrence()->addRRule(rule); // recurrence takes ownership
    }
    for (const QJsonValue &x : s.value(QLatin1String("exdates")).toArray()) {
        const QDateTime ex = toDateTime(x);
        if (ex.isValid()) ev->recurrence()->addExDateTime(ex);
    }
    for (const QJsonValue &v : s.value(QLatin1String("attendees")).toArray()) {
        const QJsonObject a = v.toObject();
        KC::Attendee attendee(a.value(QLatin1String("name")).toString(), a.value(QLatin1String("email")).toString(),
                              a.value(QLatin1String("rsvp")).toBool(),
                              partStat(a.value(QLatin1String("partstat")).toString()),
                              attendeeRole(a.value(QLatin1String("role")).toString()));
        if (!a.value(QLatin1String("cutype")).toString().isEmpty()) {
            attendee.setCuType(a.value(QLatin1String("cutype")).toString());
        }
        ev->addAttendee(attendee);
    }
    if (!text("organizer_email").isEmpty()) {
        if (text("organizer_name").isEmpty()) {
            ev->setOrganizer(text("organizer_email"));
        } else {
            ev->setOrganizer(KC::Person(text("organizer_name"), text("organizer_email")));
        }
    }
    if (text("status") == QLatin1String("CONFIRMED")) ev->setStatus(KC::Incidence::StatusConfirmed);
    else if (text("status") == QLatin1String("CANCELLED")) ev->setStatus(KC::Incidence::StatusCanceled);
    else if (text("status") == QLatin1String("TENTATIVE")) ev->setStatus(KC::Incidence::StatusTentative);
    if (s.value(QLatin1String("transparent")).toBool()) ev->setTransparency(KC::Event::Transparent);
    if (!text("color").isEmpty()) ev->setColor(text("color"));
    for (const QJsonValue &v : s.value(QLatin1String("alarms")).toArray()) {
        const QJsonObject a = v.toObject();
        KC::Alarm::Ptr alarm(new KC::Alarm(ev.data()));
        alarm->setType(a.value(QLatin1String("email")).toBool() ? KC::Alarm::Email : KC::Alarm::Display);
        alarm->setStartOffset(KC::Duration(a.value(QLatin1String("offset_secs")).toInt(), KC::Duration::Seconds));
        alarm->setEnabled(true);
        ev->addAlarm(alarm);
    }
    return ev;
}

// Our notebooks: the per-calendar ones and the retired per-account one.
QJsonObject ProtonSyncPlugin::dumpCalendar()
{
    m_dumpedEvents.clear();
    m_cal = mKCal::ExtendedCalendar::Ptr(new mKCal::ExtendedCalendar(QTimeZone::systemTimeZone()));
    m_storage = mKCal::ExtendedCalendar::defaultStorage(m_cal);
    if (!m_storage->open()) return failure(QStringLiteral("mKCal storage open failed"));
    const QString legacy = QStringLiteral("proton-calendar-%1").arg(m_accountId);
    QJsonArray notebooks;
    QJsonArray events;
    for (const mKCal::Notebook::Ptr &nb : m_storage->notebooks()) {
        if (!nb || (nb->uid() != legacy && !nb->uid().startsWith(legacy + QLatin1Char('-')))) continue;
        notebooks.append(nb->uid());
        if (!m_storage->loadNotebookIncidences(nb->uid())) {
            return failure(QStringLiteral("loadNotebookIncidences failed for ") + nb->uid());
        }
        for (const KC::Incidence::Ptr &inc : m_cal->incidences(nb->uid())) {
            const KC::Event::Ptr ev = inc.dynamicCast<KC::Event>();
            if (!ev) continue;
            events.append(eventToJson(ev, nb->uid(), false));
            m_dumpedEvents << ev;
        }
        KC::Incidence::List deleted;
        if (!m_storage->deletedIncidences(&deleted, QDateTime(), nb->uid())) continue;
        for (const KC::Incidence::Ptr &inc : deleted) {
            const KC::Event::Ptr ev = inc.dynamicCast<KC::Event>();
            if (!ev) continue;
            events.append(eventToJson(ev, nb->uid(), true));
            m_dumpedEvents << ev;
        }
    }
    return okResult(QJsonObject{{QStringLiteral("notebooks"), notebooks}, {QStringLiteral("events"), events}});
}

bool ProtonSyncPlugin::ensureNotebook(const QString &uid, const QString &name)
{
    if (m_storage->notebook(uid)) return true;
    mKCal::Notebook::Ptr nb(new mKCal::Notebook());
    nb->setUid(uid);
    nb->setName(name);
    nb->setDescription(QStringLiteral("Proton Calendar"));
    nb->setPluginName(QStringLiteral("proton"));
    nb->setAccount(m_accountId);
    nb->setSyncProfile(getProfileName());
    nb->setIsVisible(true);
    nb->setIsReadOnly(false);
    nb->setEventsAllowed(true);
    nb->setTodosAllowed(false);
    nb->setJournalsAllowed(false);
    if (!m_storage->addNotebook(nb)) return false;
    proton_log(QStringLiteral("Created calendar notebook ") + uid);
    return true;
}

// Plan steps in order: delete (dumped indexes), ensure notebooks, add,
// save purging those deletions, delete retired notebooks, report
// lastModified, purge tombstones. Nothing is saved unless every in-memory
// step succeeded.
QJsonObject ProtonSyncPlugin::writeCalendar(const QJsonObject &plan)
{
    if (!m_cal || !m_storage) return failure(QStringLiteral("calendar not loaded"));
    for (const QJsonValue &ref : plan.value(QLatin1String("delete")).toArray()) {
        const int index = ref.toInt(-1);
        if (index < 0 || index >= m_dumpedEvents.size()) return failure(QStringLiteral("delete refers to an unknown event"));
        const KC::Event::Ptr ev = m_dumpedEvents.at(index);
        // A master delete may already have taken its exceptions with it.
        if (!m_cal->deleteEvent(ev) && m_cal->event(ev->uid(), ev->recurrenceId())) {
            return failure(QStringLiteral("deleteEvent failed uid=") + ev->uid().left(64));
        }
    }
    for (const QJsonValue &v : plan.value(QLatin1String("notebooks")).toArray()) {
        const QJsonObject nb = v.toObject();
        if (!ensureNotebook(nb.value(QLatin1String("uid")).toString(), nb.value(QLatin1String("name")).toString())) {
            return failure(QStringLiteral("cannot create notebook ") + nb.value(QLatin1String("uid")).toString());
        }
    }
    for (const QJsonValue &v : plan.value(QLatin1String("add")).toArray()) {
        const QJsonObject spec = v.toObject();
        if (!m_cal->addEvent(eventFromSpec(spec), spec.value(QLatin1String("notebook")).toString())) {
            return failure(QStringLiteral("addEvent failed uid=") + spec.value(QLatin1String("uid")).toString().left(64));
        }
    }
    if (!m_storage->save(mKCal::ExtendedStorage::PurgeDeleted)) return failure(QStringLiteral("mKCal storage save failed"));
    for (const QJsonValue &v : plan.value(QLatin1String("delete_notebooks")).toArray()) {
        const mKCal::Notebook::Ptr nb = m_storage->notebook(v.toString());
        if (nb && m_storage->deleteNotebook(nb)) proton_log(QStringLiteral("Retired notebook ") + v.toString());
    }
    QJsonObject lastModified;
    for (const QJsonValue &v : plan.value(QLatin1String("report")).toArray()) {
        const KC::Event::Ptr ev = m_cal->event(v.toString());
        if (ev && ev->lastModified().isValid()) lastModified.insert(v.toString(), ev->lastModified().toMSecsSinceEpoch());
    }
    for (const QJsonValue &v : plan.value(QLatin1String("purge")).toArray()) {
        const QJsonObject purge = v.toObject();
        const QString nbUid = purge.value(QLatin1String("notebook")).toString();
        const bool all = purge.value(QLatin1String("all")).toBool();
        QSet<QString> uids;
        for (const QJsonValue &u : purge.value(QLatin1String("uids")).toArray()) uids.insert(u.toString());
        KC::Incidence::List deleted;
        if (!m_storage->deletedIncidences(&deleted, QDateTime(), nbUid) || deleted.isEmpty()) continue;
        KC::Incidence::List doomed;
        for (const KC::Incidence::Ptr &inc : deleted) {
            if (inc && (all || uids.contains(inc->uid()))) doomed.append(inc);
        }
        if (!doomed.isEmpty() && m_storage->purgeDeletedIncidences(doomed, nbUid)) {
            proton_log(QStringLiteral("Purged %1 tombstones from %2").arg(doomed.size()).arg(nbUid));
        }
    }
    return okResult(QJsonObject{{QStringLiteral("last_modified"), lastModified}});
}

// ---- loader ----

// One libproton-client.so serves both profiles (Sync Protocol "proton"),
// told apart by profile name (proton-carddav-* / proton-caldav-*).
Buteo::ClientPlugin *ProtonPluginLoader::createClientPlugin(const QString &aPluginName,
                                                            const Buteo::SyncProfile &aProfile,
                                                            Buteo::PluginCbInterface *aCbInterface)
{
    const QString name = aProfile.name();
    const bool calendar = name.contains(QStringLiteral("caldav")) || name.contains(QStringLiteral("calendar"))
        || name.contains(QStringLiteral("Calendar"));
    return new ProtonSyncPlugin(aPluginName, aProfile, aCbInterface, calendar);
}
