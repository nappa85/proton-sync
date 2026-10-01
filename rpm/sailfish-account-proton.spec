Name:           sailfish-account-proton
Summary:        Proton account provider for SailfishOS
Version:        0.1.2
Release:        1
License:        GPL-3.0-or-later
URL:            https://github.com/nappa85/proton-bridge
Source0:        %{name}-%{version}.tar.bz2

# Accounts &SSO BuildRequires not needed for file-only packaging; keep minimal for SDK
# BuildRequires:  pkgconfig(libaccounts-glib)
# BuildRequires:  pkgconfig(libsignon-glib)
Requires:       libaccounts-glib
Requires:       libsignon-glib
# Paired engine: toggles and profiles are useless without it.
Requires:       buteo-sync-plugin-proton
# sailfish-accounts-ui is virtual; real package is jolla-settings-accounts
Requires:       jolla-settings-accounts

%description
SailfishOS account provider for Proton (Mail, Contacts, Calendar).
Allows users to add Proton accounts in Settings → Accounts and sync
contacts via the buteo-sync-plugin-proton plugin.

%prep
%setup -q -n %{name}-%{version}

%build
# Nothing to build - all files are pre-staged

%install
rm -rf %{buildroot}

# Install provider description
mkdir -p %{buildroot}%{_datadir}/accounts/providers
install -m 0644 accounts/proton.provider \
    %{buildroot}%{_datadir}/accounts/providers/proton.provider

# Install service descriptions (carddav for contacts + caldav for calendar)
mkdir -p %{buildroot}%{_datadir}/accounts/services
install -m 0644 accounts/proton-carddav.service \
    %{buildroot}%{_datadir}/accounts/services/proton-carddav.service
install -m 0644 accounts/proton-caldav.service \
    %{buildroot}%{_datadir}/accounts/services/proton-caldav.service

# Install QML UI for account creation (provider id proton → proton.qml, like nextcloud.qml)
mkdir -p %{buildroot}%{_datadir}/accounts/ui
install -m 0644 ui/proton.qml \
    %{buildroot}%{_datadir}/accounts/ui/proton.qml

# Install QML UI for account settings
install -m 0644 ui/proton-settings.qml \
    %{buildroot}%{_datadir}/accounts/ui/proton-settings.qml

# Install QML UI for credentials update (OTP in-page agent)
install -m 0644 ui/proton-update.qml \
    %{buildroot}%{_datadir}/accounts/ui/proton-update.qml

# Install compiled message catalogs (built from translations/*.ts via
# tools/build-qm.sh; loaded by the Proton QML extension per locale)
mkdir -p %{buildroot}%{_datadir}/proton/translations
install -m 0644 translations/*.qm \
    %{buildroot}%{_datadir}/proton/translations/

# Install icon (to be added)
# mkdir -p %{buildroot}%{_datadir}/icons/hicolor/86x86/apps
# install -m 0644 icons/proton.png \
#     %{buildroot}%{_datadir}/icons/hicolor/86x86/apps/proton.png

%files
%defattr(-,root,root,-)
%{_datadir}/accounts/providers/proton.provider
%{_datadir}/accounts/services/proton-carddav.service
%{_datadir}/accounts/services/proton-caldav.service
%{_datadir}/accounts/ui/proton.qml
%{_datadir}/accounts/ui/proton-settings.qml
%{_datadir}/accounts/ui/proton-update.qml
%{_datadir}/proton/translations/proton_*.qm
# %{_datadir}/icons/hicolor/*/apps/proton.png

%changelog
* Sat Oct 1 2026 Marco Napetti <marco.napetti@proton.me> - 0.1.3-1
- Bulk contacts fetch, per-calendar event id
* Sat Sep 30 2026 Marco Napetti <marco.napetti@proton.me> - 0.1.2-1
- Improve performances and persistent logging
* Sat Sep 12 2026 Marco Napetti <marco.napetti@proton.me> - 0.1.1-1
- Fix CAPTCHA workflow
* Sat Sep 12 2026 Marco Napetti <marco.napetti@proton.me> - 0.1.0-1
- Initial packaging
