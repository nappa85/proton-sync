#include "proton_signon_plugin.h"
#include "proton_settings.h"

#include <QDebug>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QVariantMap>

SIGNON_DECL_AUTH_PLUGIN(ProtonSignonPlugin)

ProtonSignonPlugin::ProtonSignonPlugin(QObject *parent)
    : AuthPluginInterface(parent)
{
}

ProtonSignonPlugin::~ProtonSignonPlugin()
{
}

QString ProtonSignonPlugin::type() const
{
    return QStringLiteral("proton");
}

QStringList ProtonSignonPlugin::mechanisms() const
{
    return { QStringLiteral("password") };
}

void ProtonSignonPlugin::cancel()
{
    // Nothing to cancel: no UI interaction, no background tasks.
}

// The OTP code is intentionally never requested through signon-ui (its
// in-process entry dialog crashes this jolla-signon-ui version): account
// creation/update UIs collect it in their own QML.
void ProtonSignonPlugin::process(const SignOn::SessionData &dataIn, const QString &mechanism)
{
    Q_UNUSED(mechanism);
    run(QStringLiteral("process"), dataIn);
}

void ProtonSignonPlugin::refresh(const SignOn::UiSessionData &data)
{
    run(QStringLiteral("refresh"), data);
}

void ProtonSignonPlugin::userActionFinished(const SignOn::UiSessionData &data)
{
    Q_UNUSED(data);
    emit error(SignOn::Error(SignOn::Error::OperationNotSupported,
                             QStringLiteral("No user interaction expected")));
}

void ProtonSignonPlugin::run(const QString &mode, const SignOn::SessionData &data)
{
    QJsonObject session;
    for (const QString &name : data.propertyNames()) {
        session.insert(name, QJsonValue::fromVariant(data.getProperty(name)));
    }
    const QJsonObject input{{QStringLiteral("mode"), mode}, {QStringLiteral("data"), session}};
    char *raw = proton_signon_process(QJsonDocument(input).toJson(QJsonDocument::Compact).constData());
    const QJsonObject out = QJsonDocument::fromJson(QByteArray(raw)).object();
    proton_string_free(raw);

    for (const QJsonValue &line : out.value(QLatin1String("log")).toArray()) {
        qDebug() << "ProtonSignonPlugin:" << line.toString();
    }
    // signond may drop unknown blob keys (DerivedPasswords): the sync
    // plugin also finds them in these settings groups.
    proton_settings_apply(out.value(QLatin1String("settings")).toObject());
    if (out.value(QLatin1String("store")).isObject()) {
        emit store(SignOn::SessionData(out.value(QLatin1String("store")).toObject().toVariantMap()));
    }
    if (out.value(QLatin1String("error")).isObject()) {
        const QJsonObject err = out.value(QLatin1String("error")).toObject();
        const bool missing = err.value(QLatin1String("code")).toString() == QLatin1String("missing_data");
        emit error(SignOn::Error(missing ? SignOn::Error::MissingData : SignOn::Error::NotAuthorized,
                                 err.value(QLatin1String("message")).toString()));
        return;
    }
    emit result(SignOn::SessionData(out.value(QLatin1String("result")).toObject().toVariantMap()));
}
