#include "proton_signon_plugin.h"
#include <QDebug>
#include <QVariantMap>
#include <QSettings>

extern "C" {
    char* proton_derive_passwords(const char* password, const char* access_token, const char* uid);
    void proton_auth_free_string(char* s);
}

/*
 * Proton SignOn authentication plugin (method "proton", mechanism "password").
 *
 * signond merges the identity secret (UserName/Secret) and the previously
 * stored method blob (tokens) into the session data before invoking
 * process(), so the flow is fully driven by the input map:
 *
 *   - RefreshToken + Uid present  -> POST /auth/v4/refresh, return tokens.
 *   - Otherwise full SRP login with UserName/Secret.
 *       - account has no 2FA     -> tokens stored + returned.
 *       - account has TOTP 2FA   -> return the "Requires2FA" state through
 *                                    the result map (TwoFARequired=true +
 *                                    locked-session tokens) WITHOUT storing
 *                                    anything; the caller re-invokes the
 *                                    session with TwoFactorPassword=<code>
 *                                    (and the returned tokens) to complete.
 *
 * Tokens are persisted via the store() signal: signond keeps every property
 * except UserName/Secret in the per-identity, per-method blob store, so
 * subsequent sessions (buteo sync plugin, credentials verification) receive
 * them automatically. The user's password is never persisted by this plugin;
 * it lives only in the signond-managed identity secret.
 *
 * The OTP code is intentionally NOT requested through signon-ui
 * (userActionRequired): the in-process entry dialog crashes this
 * jolla-signon-ui version (SIGSEGV in InProcessEntryView) and the
 * NoUserInteractionPolicy used by credential verification would block it
 * anyway. Account creation/update UIs collect the code in their own QML.
 */

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

static QVariantMap tokensMap(const QString &username,
                             const QString &accessToken,
                             const QString &refreshToken,
                             const QString &uid)
{
    QVariantMap map;
    if (!username.isEmpty())
        map.insert(QStringLiteral("UserName"), username);
    if (!accessToken.isEmpty())
        map.insert(QStringLiteral("AccessToken"), accessToken);
    if (!refreshToken.isEmpty())
        map.insert(QStringLiteral("RefreshToken"), refreshToken);
    if (!uid.isEmpty())
        map.insert(QStringLiteral("Uid"), uid);
    return map;
}

void ProtonSignonPlugin::handleAuthOk(ProtonAuthResult &authResult,
                                      const QString &username,
                                      const QString &password)
{
    QString newAccess = QString::fromUtf8(authResult.access_token);
    QString newRefresh = QString::fromUtf8(authResult.refresh_token);
    QString newUid = QString::fromUtf8(authResult.uid);
    proton_auth_free_result(&authResult);

    QVariantMap tokens = tokensMap(username, newAccess, newRefresh, newUid);

    // If the raw password is available (transient "Password" param during
    // creation/update), derive mailbox passwords now and store them as
    // DerivedPasswords in the same blob. This allows future syncs to
    // unlock PGP keys without the raw password (requirement: never persist
    // raw Secret).
    // Also persist directly to QSettings as fallback, since signond may
    // filter unknown keys like DerivedPasswords from the blob.
    if (!password.isEmpty() && !newAccess.isEmpty() && !newUid.isEmpty()) {
        char* derivedJson = proton_derive_passwords(
            password.toUtf8().constData(),
            newAccess.toUtf8().constData(),
            newUid.toUtf8().constData());
        if (derivedJson) {
            QString derivedStr = QString::fromUtf8(derivedJson);
            proton_auth_free_string(derivedJson);
            if (!derivedStr.isEmpty() && derivedStr != QStringLiteral("{}") && derivedStr != QStringLiteral("null")) {
                tokens.insert(QStringLiteral("DerivedPasswords"), derivedStr);
                qDebug() << "ProtonSignonPlugin: derived" << derivedStr.length() << "chars for" << (derivedStr.count(":") ) << "keys";
                // Direct QSettings fallback for buteo sync (signond may drop DerivedPasswords)
                {
                    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
                    // Store by Uid and by username for buteo fallback
                    if (!newUid.isEmpty()) {
                        settings.beginGroup(newUid);
                        settings.setValue(QStringLiteral("derived_passwords"), derivedStr);
                        settings.endGroup();
                    }
                    if (!username.isEmpty()) {
                        settings.beginGroup(username);
                        settings.setValue(QStringLiteral("derived_passwords"), derivedStr);
                        settings.endGroup();
                    }
                    settings.sync();
                    qDebug() << "ProtonSignonPlugin: also stored DerivedPasswords in QSettings for Uid/username";
                }
            } else {
                qDebug() << "ProtonSignonPlugin: derive returned empty";
            }
        } else {
            qDebug() << "ProtonSignonPlugin: derive failed or no keys";
        }
    }

    // Persist the tokens (+ DerivedPasswords if derived) in signond's blob store
    // (UserName/Secret are stripped by signond when storing; the identity secret stays as-is,
    // but we are not storing Secret anyway – password is transient).
    emit store(SignOn::SessionData(tokens));

    QVariantMap response = tokens;
    // Do NOT return Secret/Password in the result – the raw login password
    // must not be persisted or echoed back to the client. Only tokens are
    // returned; the password is transient for SRP and for deriving mailbox
    // keys (derived passwords are cached in the blob).
    // Keep UserName for display purposes.
    if (!username.isEmpty())
        response.insert(QStringLiteral("UserName"), username);
    qDebug() << "ProtonSignonPlugin: handleAuthOk username=" << username << " pw_len=" << password.length() << " response has Secret=" << response.contains("Secret") << " has Derived=" << response.contains("DerivedPasswords");
    emit result(SignOn::SessionData(response));
}

void ProtonSignonPlugin::process(const SignOn::SessionData &dataIn, const QString &mechanism)
{
    Q_UNUSED(mechanism);

    QString username = dataIn.UserName();
    // Password is passed as transient "Password" property (not stored as Secret)
    // to avoid persisting the raw login password. Prefer Password param over
    // Secret (which now holds dummy "x").
    QString passwordParam = dataIn.getProperty(QStringLiteral("Password")).toString();
    QString password = !passwordParam.isEmpty() ? passwordParam : dataIn.Secret();
    QString refreshToken = dataIn.getProperty(QStringLiteral("RefreshToken")).toString();
    QString uid = dataIn.getProperty(QStringLiteral("Uid")).toString();
    QString totpCode = dataIn.getProperty(QStringLiteral("TwoFactorPassword")).toString().trimmed();
    QString hvToken = dataIn.getProperty(QStringLiteral("HumanVerificationToken")).toString().trimmed();
    qDebug() << "ProtonSignonPlugin: process username=" << username << " pw_len=" << password.length()
             << " rt_present=" << !refreshToken.isEmpty() << " uid=" << uid << " totp_len=" << totpCode.length()
             << " hasPasswordParam=" << !passwordParam.isEmpty() << " hv_token=" << (hvToken.isEmpty() ? "no" : "yes");

    // 1) Second factor submission: complete the locked-session login.
    if (!totpCode.isEmpty() && !refreshToken.isEmpty() && !uid.isEmpty()) {
        QString lockedAccess = dataIn.getProperty(QStringLiteral("AccessToken")).toString();
        if (!lockedAccess.isEmpty()) {
            ProtonAuthResult authResult = proton_auth_submit_2fa(
                lockedAccess.toUtf8().constData(),
                refreshToken.toUtf8().constData(),
                uid.toUtf8().constData(),
                totpCode.toUtf8().constData(),
                hvToken.toUtf8().constData());

            if (authResult.status == 0) {
                qDebug() << "ProtonSignonPlugin: 2FA verified, session upgraded";
                handleAuthOk(authResult, username, password);
            } else if (authResult.status == 3) {
                QString captchaUrl = QString::fromUtf8(authResult.captcha_url);
                QString captchaMethods = QString::fromUtf8(authResult.captcha_methods);
                QString captchaToken = QString::fromUtf8(authResult.captcha_token);
                proton_auth_free_result(&authResult);
                QVariantMap response;
                response.insert(QStringLiteral("CaptchaRequired"), true);
                response.insert(QStringLiteral("CaptchaUrl"), captchaUrl);
                response.insert(QStringLiteral("CaptchaMethods"), captchaMethods);
                response.insert(QStringLiteral("CaptchaToken"), captchaToken);
                response.insert(QStringLiteral("AccessToken"), lockedAccess);
                response.insert(QStringLiteral("RefreshToken"), refreshToken);
                response.insert(QStringLiteral("Uid"), uid);
                response.insert(QStringLiteral("TwoFARequired"), true);
                qDebug() << "ProtonSignonPlugin: CAPTCHA required on 2FA submit";
                emit result(SignOn::SessionData(response));
            } else {
                QString errMsg = QString::fromUtf8(authResult.error);
                proton_auth_free_result(&authResult);
                qWarning() << "ProtonSignonPlugin: 2FA rejected:" << errMsg;
                emit error(SignOn::Error(SignOn::Error::NotAuthorized, errMsg));
            }
            return;
        }
        // TOTP code present but no locked access token: broken state.
        emit error(SignOn::Error(SignOn::Error::MissingData,
                                 QStringLiteral("2FA code provided but no locked-session access token")));
        return;
    }

    // If a fresh password was supplied via transient "Password" param (account
    // creation / credentials update), prefer a full SRP login over a blind
    // token refresh – the refresh would succeed with the old tokens even though
    // the user just changed the password, and would never trigger the needed
    // 2FA flow.
    bool hasFreshPassword = !passwordParam.isEmpty();

    // 2) Stored tokens available: refresh, never prompt for anything.
    //    Only do this when we are NOT in a fresh-password update flow.
    if (!hasFreshPassword && !refreshToken.isEmpty() && !uid.isEmpty()) {
        ProtonAuthResult authResult = proton_auth_refresh(
            refreshToken.toUtf8().constData(),
            uid.toUtf8().constData());

        if (authResult.status == 0) {
            qDebug() << "ProtonSignonPlugin: refreshed session for uid" << uid;
            handleAuthOk(authResult, username, password);
            return;
        }

        QString err = QString::fromUtf8(authResult.error);
        proton_auth_free_result(&authResult);
        qWarning() << "ProtonSignonPlugin: token refresh failed:" << err;

        // The identity Secret is normally the dummy "x", not the login
        // password. Never attempt SRP with it after a refresh failure: that
        // produces misleading CAPTCHA challenges and unnecessary logins.
        if (password.isEmpty() || password == QStringLiteral("x")) {
            emit error(SignOn::Error(SignOn::Error::NotAuthorized,
                                     QStringLiteral("Session refresh failed: ") + err));
            return;
        }
    }

    // 3) Full SRP login.
    if (username.isEmpty() || password.isEmpty()) {
        emit error(SignOn::Error(SignOn::Error::MissingData,
                                 QStringLiteral("Username and password are required")));
        return;
    }

    ProtonAuthResult authResult = proton_auth_login(
        username.toUtf8().constData(),
        password.toUtf8().constData(),
        hvToken.toUtf8().constData());

    if (authResult.status == 0) {
        // No 2FA on the account: fully authenticated.
        handleAuthOk(authResult, username, password);
        return;
    }

    if (authResult.status == 3) {
        // Human-verification challenge (API 9001, e.g. datacenter IP
        // reputation): the credentials are fine, the NETWORK is gated. Do
        // NOT store anything; hand the challenge to the UI with the token
        // so the retry can send x-pm-humanverification. After the user
        // solves the challenge in the browser, the token is marked as
        // verified on Proton's server, and the retry with the header will
        // succeed.
        QString captchaUrl = QString::fromUtf8(authResult.captcha_url);
        QString captchaMethods = QString::fromUtf8(authResult.captcha_methods);
        QString captchaToken = QString::fromUtf8(authResult.captcha_token);
        proton_auth_free_result(&authResult);
        QVariantMap response;
        response.insert(QStringLiteral("CaptchaRequired"), true);
        response.insert(QStringLiteral("CaptchaUrl"), captchaUrl);
        response.insert(QStringLiteral("CaptchaMethods"), captchaMethods);
        response.insert(QStringLiteral("CaptchaToken"), captchaToken);
        qDebug() << "ProtonSignonPlugin: CAPTCHA required, methods=" << captchaMethods;
        emit result(SignOn::SessionData(response));
        return;
    }

    if (authResult.status == 1) {
        // 2FA required. If the caller supplied the code, finish the flow;
        // otherwise hand the locked-session tokens back (do NOT store them -
        // the session is not usable for data access until the second factor
        // is verified) so the UI can ask for the code and retry.
        QString lockedAccess = QString::fromUtf8(authResult.access_token);
        QString lockedRefresh = QString::fromUtf8(authResult.refresh_token);
        QString lockedUid = QString::fromUtf8(authResult.uid);
        proton_auth_free_result(&authResult);

        if (!totpCode.isEmpty()) {
            ProtonAuthResult twoFaResult = proton_auth_submit_2fa(
                lockedAccess.toUtf8().constData(),
                lockedRefresh.toUtf8().constData(),
                lockedUid.toUtf8().constData(),
                totpCode.toUtf8().constData(),
                hvToken.toUtf8().constData());

            if (twoFaResult.status == 0) {
                qDebug() << "ProtonSignonPlugin: 2FA verified, session upgraded";
                handleAuthOk(twoFaResult, username, password);
            } else if (twoFaResult.status == 3) {
                // Challenge on the 2FA submit itself: include locked-session
                // tokens so the retry can go straight to 2FA, not full login.
                QString captchaUrl = QString::fromUtf8(twoFaResult.captcha_url);
                QString captchaMethods = QString::fromUtf8(twoFaResult.captcha_methods);
                QString captchaToken = QString::fromUtf8(twoFaResult.captcha_token);
                proton_auth_free_result(&twoFaResult);
                QVariantMap response;
                response.insert(QStringLiteral("CaptchaRequired"), true);
                response.insert(QStringLiteral("CaptchaUrl"), captchaUrl);
                response.insert(QStringLiteral("CaptchaMethods"), captchaMethods);
                response.insert(QStringLiteral("CaptchaToken"), captchaToken);
                response.insert(QStringLiteral("AccessToken"), lockedAccess);
                response.insert(QStringLiteral("RefreshToken"), lockedRefresh);
                response.insert(QStringLiteral("Uid"), lockedUid);
                response.insert(QStringLiteral("TwoFARequired"), true);
                qDebug() << "ProtonSignonPlugin: CAPTCHA required on 2FA submit";
                emit result(SignOn::SessionData(response));
            } else {
                QString errMsg = QString::fromUtf8(twoFaResult.error);
                proton_auth_free_result(&twoFaResult);
                qWarning() << "ProtonSignonPlugin: 2FA rejected:" << errMsg;
                emit error(SignOn::Error(SignOn::Error::NotAuthorized, errMsg));
            }
            return;
        }

        QVariantMap response;
        response.insert(QStringLiteral("TwoFARequired"), true);
        response.insert(QStringLiteral("AccessToken"), lockedAccess);
        response.insert(QStringLiteral("RefreshToken"), lockedRefresh);
        response.insert(QStringLiteral("Uid"), lockedUid);
        qDebug() << "ProtonSignonPlugin: 2FA required, returning locked session";
        emit result(SignOn::SessionData(response));
        return;
    }

    QString errMsg = QString::fromUtf8(authResult.error);
    proton_auth_free_result(&authResult);
    emit error(SignOn::Error(SignOn::Error::NotAuthorized, errMsg));
}

void ProtonSignonPlugin::userActionFinished(const SignOn::UiSessionData &data)
{
    Q_UNUSED(data);
    // No UI interaction is requested by this plugin.
    emit error(SignOn::Error(SignOn::Error::OperationNotSupported,
                             QStringLiteral("No user interaction expected")));
}

void ProtonSignonPlugin::refresh(const SignOn::UiSessionData &data)
{
    QString refreshToken = data.getProperty(QStringLiteral("RefreshToken")).toString();
    QString uid = data.getProperty(QStringLiteral("Uid")).toString();
    QString username = data.UserName();

    if (refreshToken.isEmpty() || uid.isEmpty()) {
        emit error(SignOn::Error(SignOn::Error::MissingData,
                                 QStringLiteral("No stored tokens to refresh")));
        return;
    }

    ProtonAuthResult authResult = proton_auth_refresh(
        refreshToken.toUtf8().constData(),
        uid.toUtf8().constData());

    if (authResult.status == 0) {
        handleAuthOk(authResult, username, QString());
        return;
    }

    QString errMsg = QString::fromUtf8(authResult.error);
    proton_auth_free_result(&authResult);
    emit error(SignOn::Error(SignOn::Error::NotAuthorized, errMsg));
}
