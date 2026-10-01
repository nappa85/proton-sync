#include "../calendar_identity.h"

#include <QSet>
#include <cstdio>
#include <cstdlib>

static void check(bool condition, const char *message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}

int main() {
    using namespace Proton::CalendarIdentity;
    const QString meeting = QStringLiteral("6r904ZblLJdlpyRzSkQbUfxxtKtU@proton.me");
    QSet<QString> identities;
    for (const QString &calendar : {QStringLiteral("personal"), QStringLiteral("shared")}) {
        for (qint64 recurrence : {qint64(0), qint64(1789502400)}) {
            QString stored = storedUid("143", calendar, meeting, recurrence);
            check(!identities.contains(stored), "calendar/recurrence copies must coexist");
            identities.insert(stored);
            check(rawUid(stored, "143", calendar) == meeting, "wire UID must survive round trip");
        }
    }
    check(storedUid("144", "personal", meeting) != storedUid("143", "personal", meeting),
          "accounts must remain separate");
    check(rawUid("proton-cal-143-" + meeting, "143", "personal") == meeting,
          "legacy master migration");
    check(rawUid("proton-cal-143-" + meeting + "#1789502400", "143", "personal") == meeting,
          "legacy exception migration");
    check(storedUid("143", "", meeting) == storedUid("143", "default", meeting),
          "default calendar normalization");
    const QString unusual = QString::fromUtf8("meeting:#123/è@example.org");
    check(rawUid(storedUid("143", "cal:/#", unusual, 200), "143", "cal:/#") == unusual,
          "wire separators and Unicode must not become recurrence or calendar delimiters");
    check(storedUid("143", "personal", "meeting#200") != storedUid("143", "personal", "meeting", 200),
          "master UID suffix must not collide with an exception");
    std::puts("Calendar identity regression checks passed");
    return 0;
}
