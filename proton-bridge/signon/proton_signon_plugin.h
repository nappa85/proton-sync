#pragma once

#include <SignOn/authpluginif.h>
#include "proton_bridge.h"

// SignOn authentication plugin (method "proton", mechanism "password").
// The login / refresh / 2FA / human-verification flow lives in Rust
// (proton-bridge/src/auth.rs); this class forwards the session map and
// emits what comes back.
class ProtonSignonPlugin : public AuthPluginInterface
{
    Q_OBJECT
    Q_INTERFACES(AuthPluginInterface)

public:
    ProtonSignonPlugin(QObject *parent = nullptr);
    ~ProtonSignonPlugin() override;

    QString type() const override;
    QStringList mechanisms() const override;
    void cancel() override;
    void process(const SignOn::SessionData &inData, const QString &mechanism = QString()) override;
    void userActionFinished(const SignOn::UiSessionData &data) override;
    void refresh(const SignOn::UiSessionData &data) override;

private:
    void run(const QString &mode, const SignOn::SessionData &data);
};
