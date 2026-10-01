#!/usr/bin/env bash
# Build Proton Contacts Buteo sync plugin + SignOn auth plugin
# 1. Cross-compile Rust staticlib (aarch64-unknown-linux-gnu)
# 2. Compile C++ Buteo plugin + SignOn plugin + link (SDK container)
# 3. Deploy to phone
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
packaging_dir="$repo_root/packaging"
target_triple="aarch64-unknown-linux-gnu"

# Ensure packaging dir exists and is writable (CI: runner user must own it)
mkdir -p "$packaging_dir"
# In CI, previous container runs may have created root-owned dirs; fix ownership
chmod -R u+rwX "$packaging_dir" 2>/dev/null || true

mkdir -p "$packaging_dir/buteo-plugin" \
         "$packaging_dir/signon-plugin" \
         "$packaging_dir/accounts" \
         "$packaging_dir/ui" \
         "$packaging_dir/rpm" \
         "$packaging_dir/buteo-profiles/client" \
         "$packaging_dir/buteo-profiles/sync"

echo "========================================="
echo " Step 1: Cross-compile Rust for aarch64 "
echo "========================================="

if [ "${SKIP_RUST_DOCKER:-0}" != "1" ]; then
docker run --rm -v "$repo_root":/workspace proton-build-env bash -c '
set -e
cd /workspace
export CARGO_HOME=/workspace/.cargo-home
cargo build --release --target aarch64-unknown-linux-gnu -p proton-bridge 2>&1 | tail -5
'
else
    # CI release path: the workflow already cross-compiled the workspace
    # (same target/triple/profile) on the runner, so reuse that artifact
    # instead of requiring the local-only proton-build-env image.
    echo "(SKIP_RUST_DOCKER=1: using prebuilt libproton_bridge.a)"
fi

if [ ! -f "$repo_root/target/$target_triple/release/libproton_bridge.a" ]; then
    echo "ERROR: libproton_bridge.a not found"
    exit 1
fi

echo "========================================="
echo " Step 2: Compile C++ plugins             "
echo "========================================="

# Prepare Buteo plugin sources
cp "$repo_root/proton-bridge/cxx/proton_bridge_shim.h" "$packaging_dir/buteo-plugin/"
cp "$repo_root/proton-bridge/cxx/proton_bridge_shim.cpp" "$packaging_dir/buteo-plugin/"
cp "$repo_root/proton-bridge/cxx/calendar_identity.h" "$packaging_dir/buteo-plugin/"
cp "$repo_root/proton-bridge/proton_log.h" "$packaging_dir/buteo-plugin/"
cp "$repo_root/proton-bridge/proton_bridge.h" "$packaging_dir/buteo-plugin/"
cp "$repo_root/target/$target_triple/release/libproton_bridge.a" "$packaging_dir/buteo-plugin/"

# Prepare Settings QML extension sources (purge helper for proton-settings.qml)
mkdir -p "$packaging_dir/settings-plugin"
cp "$repo_root/proton-bridge/settings/protonsettingsplugin.h" "$packaging_dir/settings-plugin/"
cp "$repo_root/proton-bridge/settings/protonsettingsplugin.cpp" "$packaging_dir/settings-plugin/"
cp "$repo_root/proton-bridge/proton_log.h" "$packaging_dir/settings-plugin/"
cp "$repo_root/proton-bridge/settings/qmldir" "$packaging_dir/settings-plugin/"

# Prepare SignOn plugin sources
mkdir -p "$packaging_dir/signon-plugin/SignOn"
cp "$repo_root/proton-bridge/signon/proton_signon_plugin.h" "$packaging_dir/signon-plugin/"
cp "$repo_root/proton-bridge/signon/proton_signon_plugin.cpp" "$packaging_dir/signon-plugin/"
cp "$repo_root/proton-bridge/signon/SignOn/authpluginif.h" "$packaging_dir/signon-plugin/SignOn/"
cp "$repo_root/proton-bridge/signon/SignOn/uisessiondata.h" "$packaging_dir/signon-plugin/SignOn/"
if [ -f "$repo_root/proton-bridge/signon/minimal_authpluginif.h" ]; then
    cp "$repo_root/proton-bridge/signon/minimal_authpluginif.h" "$packaging_dir/signon-plugin/"
fi
# proton plugin json is proton_plugin.json (not proton.json)
if [ -f "$repo_root/proton-bridge/signon/proton_plugin.json" ]; then
    cp "$repo_root/proton-bridge/signon/proton_plugin.json" "$packaging_dir/signon-plugin/proton.json"
elif [ -f "$repo_root/proton-bridge/signon/proton.json" ]; then
    cp "$repo_root/proton-bridge/signon/proton.json" "$packaging_dir/signon-plugin/"
fi
cp "$repo_root/proton-bridge/proton_bridge.h" "$packaging_dir/signon-plugin/"
cp "$repo_root/target/$target_triple/release/libproton_bridge.a" "$packaging_dir/signon-plugin/"

# Vendor Buteo headers (buteo-syncfw is gitignored; these are stable)
mkdir -p "$packaging_dir/buteo-headers"
cp -r "$repo_root/buteo-headers/"* "$packaging_dir/buteo-headers/"

# Device-versioned mKCal/KCalendarCore headers (exact -devel RPM content from
# the phone: mkcal-qt5-devel-0.7.33, kf5-calendarcore-devel-5.116.0). The SDK
# sysroot ships the .so files but not these headers.
mkdir -p "$packaging_dir/device-headers"
cp -r "$repo_root/proton-bridge/device-headers/mkcal-qt5" "$packaging_dir/device-headers/"
cp -r "$repo_root/proton-bridge/device-headers/KF5" "$packaging_dir/device-headers/"

docker run --rm --user root \
    -v "$packaging_dir":/home/mersdk/packaging \
    coderus/sailfishos-platform-sdk-aarch64 bash -c '
set -e
export PATH="/opt/cross/bin:$PATH"
export TARGET_ROOT="/srv/mer/targets/SailfishOS-5.2.0.15-aarch64"
export TOOLING_ROOT="/srv/mer/toolings/SailfishOS-5.2.0.15"
export MOC="$TOOLING_ROOT/usr/lib/qt5/bin/moc"

chown -R 1000:1000 /home/mersdk/packaging/

# Fix assembler symlink
ln -sf /opt/cross/bin/aarch64-meego-linux-gnu-as /opt/cross/bin/as 2>/dev/null || true

# Setup dev symlinks
ln -sf libbuteosyncfw5.so.0 $TARGET_ROOT/usr/lib64/libbuteosyncfw5.so 2>/dev/null || true
ln -sf libQt5Core.so.5 $TARGET_ROOT/usr/lib64/libQt5Core.so 2>/dev/null || true
ln -sf libQt5Contacts.so.5 $TARGET_ROOT/usr/lib64/libQt5Contacts.so 2>/dev/null || true
ln -sf libmkcal-qt5.so.0 $TARGET_ROOT/usr/lib64/libmkcal-qt5.so 2>/dev/null || true
ln -sf libKF5CalendarCore.so.5 $TARGET_ROOT/usr/lib64/libKF5CalendarCore.so 2>/dev/null || true
ln -sf libaccounts-qt5.so.1 $TARGET_ROOT/usr/lib64/libaccounts-qt5.so 2>/dev/null || true
ln -sf libsignon-qt5.so.1 $TARGET_ROOT/usr/lib64/libsignon-qt5.so 2>/dev/null || true
ln -sf libsignon-plugins-common.so.1 $TARGET_ROOT/usr/lib64/libsignon-plugins-common.so 2>/dev/null || true
ln -sf libQt5DBus.so.5 $TARGET_ROOT/usr/lib64/libQt5DBus.so 2>/dev/null || true
ln -sf libQt5Qml.so.5 $TARGET_ROOT/usr/lib64/libQt5Qml.so 2>/dev/null || true
ln -sf libQt5Quick.so.5 $TARGET_ROOT/usr/lib64/libQt5Quick.so 2>/dev/null || true
ln -sf libQt5Xml.so.5 $TARGET_ROOT/usr/lib64/libQt5Xml.so 2>/dev/null || true
ln -sf libQt5Network.so.5 $TARGET_ROOT/usr/lib64/libQt5Network.so 2>/dev/null || true

BUTEO_INC="-I/home/mersdk/packaging/buteo-headers \
    -I/home/mersdk/packaging/device-headers/mkcal-qt5 \
    -I/home/mersdk/packaging/device-headers/KF5 \
    -I/home/mersdk/packaging/device-headers/KF5/KCalendarCore \
    -I$TARGET_ROOT/usr/include/qt5 \
    -I$TARGET_ROOT/usr/include/qt5/QtCore \
    -I$TARGET_ROOT/usr/include/qt5/QtGui \
    -I$TARGET_ROOT/usr/include/qt5/QtContacts \
    -I$TARGET_ROOT/usr/include/qt5/QtDBus \
    -I$TARGET_ROOT/usr/include/qt5/QtXml \
    -I$TARGET_ROOT/usr/include/qt5/QtNetwork \
    -I$TARGET_ROOT/usr/include/accounts-qt5 \
    -I$TARGET_ROOT/usr/include/signon-qt5 \
    -I$TARGET_ROOT/usr/include \
    -DQT_CORE_LIB"

SIGNON_INC="-I/home/mersdk/packaging/signon-plugin \
    -I$TARGET_ROOT/usr/include/qt5 \
    -I$TARGET_ROOT/usr/include/qt5/QtCore \
    -I$TARGET_ROOT/usr/include/signon-qt5 \
    -I$TARGET_ROOT/usr/include \
    -DQT_CORE_LIB"

# === Buteo plugin ===

# Moc
$MOC $BUTEO_INC \
    /home/mersdk/packaging/buteo-plugin/proton_bridge_shim.h \
    -o /home/mersdk/packaging/buteo-plugin/moc_proton_bridge_shim.cpp

# Compile
aarch64-meego-linux-gnu-g++ \
    -std=c++14 -c -fPIC --sysroot=$TARGET_ROOT \
    $BUTEO_INC \
    -o /home/mersdk/packaging/buteo-plugin/shim.o \
    /home/mersdk/packaging/buteo-plugin/proton_bridge_shim.cpp

aarch64-meego-linux-gnu-g++ \
    -std=c++14 -c -fPIC --sysroot=$TARGET_ROOT \
    $BUTEO_INC \
    -o /home/mersdk/packaging/buteo-plugin/moc_shim.o \
    /home/mersdk/packaging/buteo-plugin/moc_proton_bridge_shim.cpp

# Link
rm -f /home/mersdk/packaging/buteo-plugin/libproton-client.so
aarch64-meego-linux-gnu-g++ \
    -shared -fPIC --sysroot=$TARGET_ROOT \
    -o /home/mersdk/packaging/buteo-plugin/libproton-client.so \
    /home/mersdk/packaging/buteo-plugin/shim.o \
    /home/mersdk/packaging/buteo-plugin/moc_shim.o \
    -L$TARGET_ROOT/usr/lib64 \
    /home/mersdk/packaging/buteo-plugin/libproton_bridge.a \
    -lbuteosyncfw5 \
    -lQt5Core \
    -lQt5Gui \
    -lQt5Contacts \
    -lmkcal-qt5 \
    -lKF5CalendarCore \
    -lQt5DBus \
    -lQt5Xml \
    -lQt5Network \
    -laccounts-qt5 \
    -lsignon-qt5 \
    -lpthread -ldl -lm

chown 1000:1000 /home/mersdk/packaging/buteo-plugin/libproton-client.so
echo "Buteo plugin built successfully"
ls -lh /home/mersdk/packaging/buteo-plugin/libproton-client.so

# === SignOn plugin ===

# Moc
$MOC $SIGNON_INC \
    /home/mersdk/packaging/signon-plugin/proton_signon_plugin.h \
    -o /home/mersdk/packaging/signon-plugin/moc_proton_signon_plugin.cpp

# Compile
aarch64-meego-linux-gnu-g++ \
    -std=c++14 -c -fPIC --sysroot=$TARGET_ROOT \
    $SIGNON_INC \
    -o /home/mersdk/packaging/signon-plugin/signon_plugin.o \
    /home/mersdk/packaging/signon-plugin/proton_signon_plugin.cpp

aarch64-meego-linux-gnu-g++ \
    -std=c++14 -c -fPIC --sysroot=$TARGET_ROOT \
    $SIGNON_INC \
    -o /home/mersdk/packaging/signon-plugin/moc_signon_plugin.o \
    /home/mersdk/packaging/signon-plugin/moc_proton_signon_plugin.cpp

# Link – filename must match Type in json (proton -> libprotonplugin.so per Sailfish convention)
rm -f /home/mersdk/packaging/signon-plugin/libprotonplugin.so
rm -f /home/mersdk/packaging/signon-plugin/libproton.so
aarch64-meego-linux-gnu-g++ \
    -shared -fPIC --sysroot=$TARGET_ROOT \
    -o /home/mersdk/packaging/signon-plugin/libprotonplugin.so \
    /home/mersdk/packaging/signon-plugin/signon_plugin.o \
    /home/mersdk/packaging/signon-plugin/moc_signon_plugin.o \
    -L$TARGET_ROOT/usr/lib64 \
    /home/mersdk/packaging/signon-plugin/libproton_bridge.a \
    -lsignon-qt5 \
    -lsignon-plugins-common \
    -lQt5Core \
    -lQt5Network \
    -lpthread -ldl -lm

chown 1000:1000 /home/mersdk/packaging/signon-plugin/libprotonplugin.so
echo "SignOn plugin built successfully"
ls -lh /home/mersdk/packaging/signon-plugin/libprotonplugin.so

# === Settings QML extension (purge helper, no Rust linkage) ===

SETTINGS_INC="-I/home/mersdk/packaging/settings-plugin \
    -I/home/mersdk/packaging/device-headers/mkcal-qt5 \
    -I/home/mersdk/packaging/device-headers/KF5 \
    -I/home/mersdk/packaging/device-headers/KF5/KCalendarCore \
    -I$TARGET_ROOT/usr/include/qt5 \
    -I$TARGET_ROOT/usr/include/qt5/QtCore \
    -I$TARGET_ROOT/usr/include/qt5/QtGui \
    -I$TARGET_ROOT/usr/include/qt5/QtQml \
    -I$TARGET_ROOT/usr/include/qt5/QtQuick \
    -I$TARGET_ROOT/usr/include/qt5/QtContacts \
    -I$TARGET_ROOT/usr/include \
    -DQT_CORE_LIB"

$MOC $SETTINGS_INC \
    /home/mersdk/packaging/settings-plugin/protonsettingsplugin.h \
    -o /home/mersdk/packaging/settings-plugin/moc_protonsettingsplugin.cpp

aarch64-meego-linux-gnu-g++ \
    -std=c++14 -c -fPIC --sysroot=$TARGET_ROOT \
    $SETTINGS_INC \
    -o /home/mersdk/packaging/settings-plugin/settings_plugin.o \
    /home/mersdk/packaging/settings-plugin/protonsettingsplugin.cpp

aarch64-meego-linux-gnu-g++ \
    -std=c++14 -c -fPIC --sysroot=$TARGET_ROOT \
    $SETTINGS_INC \
    -o /home/mersdk/packaging/settings-plugin/moc_settings_plugin.o \
    /home/mersdk/packaging/settings-plugin/moc_protonsettingsplugin.cpp

rm -f /home/mersdk/packaging/settings-plugin/libprotonsettingsplugin.so
aarch64-meego-linux-gnu-g++ \
    -shared -fPIC --sysroot=$TARGET_ROOT \
    -o /home/mersdk/packaging/settings-plugin/libprotonsettingsplugin.so \
    /home/mersdk/packaging/settings-plugin/settings_plugin.o \
    /home/mersdk/packaging/settings-plugin/moc_settings_plugin.o \
    -L$TARGET_ROOT/usr/lib64 \
    -lQt5Core \
    -lQt5Qml \
    -lQt5Contacts \
    -lmkcal-qt5 \
    -lKF5CalendarCore \
    -lpthread -ldl -lm

chown 1000:1000 /home/mersdk/packaging/settings-plugin/libprotonsettingsplugin.so
echo "Settings plugin built successfully"
ls -lh /home/mersdk/packaging/settings-plugin/libprotonsettingsplugin.so
'

echo "========================================="
echo " Step 2b: Assemble RPM tarballs          "
echo "========================================="

# Deterministic tarballs from the repo tree (version follows the workspace
# Cargo.toml, which release stamping updates BEFORE this script runs).
# The old checked-in/stale tarballs shipped ancient sources (missing
# proton-caldav.service, proton-update.qml, settings-plugin) and even
# contained .o junk — never reuse them.
PKG_VER="$(grep -m1 '^version = ' "$repo_root/Cargo.toml" | cut -d'"' -f2)"
if [ -z "$PKG_VER" ]; then
    echo "ERROR: cannot parse version from Cargo.toml"
    exit 1
fi
echo "Packaging version $PKG_VER"

# Build RPM source trees in a temp dir under repo_root (guaranteed
# writable by the runner) to avoid any permission issues with
# packaging/ which may have been created by docker as root.
rpm_src="$repo_root/rpmbuild-tmp"
rm -rf "$rpm_src"
mkdir -p "$rpm_src/buteo-sync-plugin-proton-$PKG_VER/buteo-plugin" \
         "$rpm_src/buteo-sync-plugin-proton-$PKG_VER/buteo-profiles/client" \
         "$rpm_src/buteo-sync-plugin-proton-$PKG_VER/buteo-profiles/sync" \
         "$rpm_src/buteo-sync-plugin-proton-$PKG_VER/settings-plugin" \
         "$rpm_src/sailfish-account-proton-$PKG_VER/ui" \
         "$rpm_src/sailfish-account-proton-$PKG_VER/accounts" \
         "$rpm_src/sailfish-account-proton-$PKG_VER/translations"

# Buteo plugin RPM contents: built .so files + install-time data only
# (no .o/.a/moc intermediates).
cp "$packaging_dir/buteo-plugin/libproton-client.so" \
   "$rpm_src/buteo-sync-plugin-proton-$PKG_VER/buteo-plugin/"
cp "$repo_root/proton-bridge/cxx/proton_bridge_shim.h" \
   "$repo_root/proton-bridge/cxx/proton_bridge_shim.cpp" \
   "$repo_root/proton-bridge/proton_bridge.h" \
   "$repo_root/proton-bridge/cxx/calendar_identity.h" \
   "$rpm_src/buteo-sync-plugin-proton-$PKG_VER/buteo-plugin/"
cp "$repo_root/buteo-profiles/client/proton-contacts.xml" \
   "$rpm_src/buteo-sync-plugin-proton-$PKG_VER/buteo-profiles/client/"
cp "$repo_root/buteo-profiles/sync/proton.Contacts.xml" \
   "$repo_root/buteo-profiles/sync/proton.Calendar.xml" \
   "$rpm_src/buteo-sync-plugin-proton-$PKG_VER/buteo-profiles/sync/"
cp "$packaging_dir/settings-plugin/libprotonsettingsplugin.so" \
   "$rpm_src/buteo-sync-plugin-proton-$PKG_VER/settings-plugin/"
cp "$repo_root/proton-bridge/settings/qmldir" \
   "$rpm_src/buteo-sync-plugin-proton-$PKG_VER/settings-plugin/"
cp "$repo_root/rpm/buteo-sync-plugin-proton.spec" \
   "$rpm_src/buteo-sync-plugin-proton-$PKG_VER/"
# Copy spec files so the CI RPM build step can find them at
# rpmbuild-tmp/rpm/<name>.spec (mb2 uses -s ../rpm/<spec>).
mkdir -p "$rpm_src/rpm"
cp "$repo_root/rpm/buteo-sync-plugin-proton.spec" \
   "$rpm_src/rpm/buteo-sync-plugin-proton.spec"
cp "$repo_root/rpm/sailfish-account-proton.spec" \
   "$rpm_src/rpm/sailfish-account-proton.spec"

# Account RPM contents: current UI + provider/services (no deleted files).
cp "$repo_root/ui/proton.qml" "$repo_root/ui/proton-settings.qml" "$repo_root/ui/proton-update.qml" \
   "$rpm_src/sailfish-account-proton-$PKG_VER/ui/"
# Compiled message catalogs (built from translations/*.ts; missing .qm
# files are a hard error — UI strings must never ship untranslated by
# accident; build them with tools/build-qm.sh).
for qm in "$repo_root"/translations/*.qm; do
    [ -e "$qm" ] || { echo "ERROR: no .qm catalogs in translations/ (run tools/build-qm.sh)"; exit 1; }
    cp "$qm" "$rpm_src/sailfish-account-proton-$PKG_VER/translations/"
done
cp "$repo_root/packaging/accounts/proton.provider" \
   "$repo_root/packaging/accounts/proton-carddav.service" \
   "$repo_root/packaging/accounts/proton-caldav.service" \
   "$rpm_src/sailfish-account-proton-$PKG_VER/accounts/"
cp "$repo_root/rpm/sailfish-account-proton.spec" \
   "$rpm_src/sailfish-account-proton-$PKG_VER/"

tar -cjf "$rpm_src/buteo-sync-plugin-proton-$PKG_VER.tar.bz2" \
    -C "$rpm_src" "buteo-sync-plugin-proton-$PKG_VER"
tar -cjf "$rpm_src/sailfish-account-proton-$PKG_VER.tar.bz2" \
    -C "$rpm_src" "sailfish-account-proton-$PKG_VER"
echo "Tarballs ready:"
tar -tf "$rpm_src/buteo-sync-plugin-proton-$PKG_VER.tar.bz2" | sort | head -20
tar -tf "$rpm_src/sailfish-account-proton-$PKG_VER.tar.bz2" | sort

echo "========================================="
echo " Step 3: Deploy to phone                 "
echo "========================================="

# Usage: ./make-pkg-bundle.sh [PHONE_IP] [--no-deploy]
# --no-deploy (or SKIP_DEPLOY=1) builds everything but skips all ssh/scp
# contact with the phone.
SKIP_DEPLOY="${SKIP_DEPLOY:-0}"
PHONE_IP="192.168.1.124"
for arg in "$@"; do
    case "$arg" in
        --no-deploy) SKIP_DEPLOY=1 ;;
        *) PHONE_IP="$arg" ;;
    esac
done
if [ "$SKIP_DEPLOY" = "1" ]; then
    echo "Skipping deploy (--no-deploy). Artifacts are in $rpm_src."
    echo "Done. Copy to phone manually, then test with: ssh defaultuser@$PHONE_IP 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/100000/dbus/user_bus_socket dbus-send --session --print-reply --dest=com.meego.msyncd /synchronizer com.meego.msyncd.startSync string:proton.Contacts-2'"
    exit 0
fi
BUTEO_PLUGIN="$packaging_dir/buteo-plugin/libproton-client.so"
# Plugin is now correctly named libprotonplugin.so
if [ -f "$packaging_dir/signon-plugin/libprotonplugin.so" ]; then
    SIGNON_PLUGIN="$packaging_dir/signon-plugin/libprotonplugin.so"
else
    SIGNON_PLUGIN="$packaging_dir/signon-plugin/libproton.so"
fi

echo "Deploying to $PHONE_IP..."
scp "$BUTEO_PLUGIN" defaultuser@$PHONE_IP:/tmp/libproton-client.so
scp "$SIGNON_PLUGIN" defaultuser@$PHONE_IP:/tmp/libprotonplugin.so

# Copy profiles (contacts + calendar, single proton client)
scp "$repo_root/buteo-profiles/client/proton-contacts.xml" defaultuser@$PHONE_IP:/tmp/
scp "$repo_root/buteo-profiles/sync/proton.Contacts.xml" defaultuser@$PHONE_IP:/tmp/
scp "$repo_root/buteo-profiles/sync/proton.Calendar.xml" defaultuser@$PHONE_IP:/tmp/proton.Calendar.xml

# Copy account XMLs (provider + both services)
scp "$repo_root/packaging/accounts/proton.provider" defaultuser@$PHONE_IP:/tmp/
scp "$repo_root/packaging/accounts/proton-carddav.service" defaultuser@$PHONE_IP:/tmp/
scp "$repo_root/packaging/accounts/proton-caldav.service" defaultuser@$PHONE_IP:/tmp/
scp "$repo_root/ui/proton.qml" defaultuser@$PHONE_IP:/tmp/proton.qml
scp "$repo_root/ui/proton-settings.qml" defaultuser@$PHONE_IP:/tmp/proton-settings.qml
scp "$repo_root/ui/proton-update.qml" defaultuser@$PHONE_IP:/tmp/proton-update.qml
scp "$packaging_dir/settings-plugin/libprotonsettingsplugin.so" defaultuser@$PHONE_IP:/tmp/libprotonsettingsplugin.so
scp "$repo_root/proton-bridge/settings/qmldir" defaultuser@$PHONE_IP:/tmp/proton-qmldir
scp "$repo_root"/translations/*.qm defaultuser@$PHONE_IP:/tmp/

ssh defaultuser@$PHONE_IP "
set -e
# Install plugins (need root for /usr/lib64)
devel-su bash -c '
cp /tmp/libproton-client.so /usr/lib64/buteo-plugins-qt5/oopp/libproton-client.so
chmod 755 /usr/lib64/buteo-plugins-qt5/oopp/libproton-client.so
rm -f /usr/lib64/buteo-plugins-qt5/oopp/libproton-contacts-client.so
rm -f /usr/lib64/buteo-plugins-qt5/oopp/proton-contacts-client.so

mkdir -p /usr/lib64/signon
cp /tmp/libprotonplugin.so /usr/lib64/signon/libprotonplugin.so
chmod 755 /usr/lib64/signon/libprotonplugin.so
# Remove old incorrect location
rm -f /usr/lib/signon/libproton.so
rm -f /usr/lib64/signon/libproton.so

cp /tmp/proton-contacts.xml /etc/buteo/profiles/client/proton.xml
# Sync profiles: proton-carddav (contacts) + proton-caldav (calendar) — single proton client
cp /tmp/proton.Contacts.xml /etc/buteo/profiles/sync/proton-carddav.xml
cp /tmp/proton.Contacts.xml /etc/buteo/profiles/sync/proton.Contacts.xml
cp /tmp/proton.Calendar.xml /etc/buteo/profiles/sync/proton-caldav.xml
cp /tmp/proton.Calendar.xml /etc/buteo/profiles/sync/proton.Calendar.xml
rm -f /etc/buteo/profiles/sync/proton.xml 2>/dev/null || true

mkdir -p /usr/share/accounts/providers
cp /tmp/proton.provider /usr/share/accounts/providers/proton.provider
mkdir -p /usr/share/accounts/services
cp /tmp/proton-carddav.service /usr/share/accounts/services/proton-carddav.service
cp /tmp/proton-caldav.service /usr/share/accounts/services/proton-caldav.service
mkdir -p /usr/share/accounts/ui
cp /tmp/proton.qml /usr/share/accounts/ui/proton.qml
cp /tmp/proton-settings.qml /usr/share/accounts/ui/proton-settings.qml
cp /tmp/proton-update.qml /usr/share/accounts/ui/proton-update.qml
rm -f /usr/share/accounts/ui/proton-creation.qml

# QML settings extension (ProtonDataPurger for the purge menu item)
mkdir -p /usr/lib64/qt5/qml/Proton
cp /tmp/libprotonsettingsplugin.so /usr/lib64/qt5/qml/Proton/libprotonsettingsplugin.so
chmod 755 /usr/lib64/qt5/qml/Proton/libprotonsettingsplugin.so
cp /tmp/proton-qmldir /usr/lib64/qt5/qml/Proton/qmldir
chmod 644 /usr/lib64/qt5/qml/Proton/qmldir

# Message catalogs for the account QML agents (loaded per locale by the
# Proton QML extension — see initializeEngine)
mkdir -p /usr/share/proton/translations
cp /tmp/proton_*.qm /usr/share/proton/translations/
chmod 644 /usr/share/proton/translations/proton_*.qm
'

# Restart msyncd
systemctl --user restart msyncd
sleep 2
echo 'Deployed!'
" 2>&1

echo "Done. Test with: ssh defaultuser@$PHONE_IP 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/100000/dbus/user_bus_socket dbus-send --session --print-reply --dest=com.meego.msyncd /synchronizer com.meego.msyncd.startSync string:proton.Contacts-2'"
