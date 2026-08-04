package io.xlogistx.nosneak.app.ui;

import org.junit.jupiter.api.Test;
import org.zoxweb.shared.crypto.CIPassword;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Pins the credentials-list password row label ({@link SubjectPanel#passwordLabel}):
 * "set" when no timestamp exists, "changed today" inside a day, singular/plural day
 * counts after that. Prefers {@code lastTimeUpdated} (stamped by
 * {@code Session.changePassword}) and falls back to creation time.
 */
public class PasswordLabelTest {

    private static final long DAY = 86_400_000L;

    private static CIPassword password(long creation, long lastUpdated) {
        CIPassword p = new CIPassword();
        p.setCreationTime(creation);
        p.setLastTimeUpdated(lastUpdated);
        return p;
    }

    @Test
    public void noTimestampReadsSet() {
        assertEquals("Password — set", SubjectPanel.passwordLabel(password(0, 0)));
    }

    @Test
    public void sameDayReadsChangedToday() {
        assertEquals("Password — set · changed today",
                SubjectPanel.passwordLabel(password(0, System.currentTimeMillis())));
    }

    @Test
    public void singleDayIsSingular() {
        long ts = System.currentTimeMillis() - DAY - 3_600_000L;
        assertEquals("Password — set · last changed 1 day ago",
                SubjectPanel.passwordLabel(password(0, ts)));
    }

    @Test
    public void multipleDaysArePlural() {
        long ts = System.currentTimeMillis() - 3 * DAY - 3_600_000L;
        assertEquals("Password — set · last changed 3 days ago",
                SubjectPanel.passwordLabel(password(0, ts)));
    }

    @Test
    public void fallsBackToCreationTimeWhenNeverUpdated() {
        long ts = System.currentTimeMillis() - 2 * DAY - 3_600_000L;
        assertEquals("Password — set · last changed 2 days ago",
                SubjectPanel.passwordLabel(password(ts, 0)));
    }

    @Test
    public void updateWinsOverCreation() {
        long creation = System.currentTimeMillis() - 10 * DAY;
        assertEquals("Password — set · changed today",
                SubjectPanel.passwordLabel(password(creation, System.currentTimeMillis())));
    }
}
