package io.xlogistx.nosneak.app;

import org.junit.jupiter.api.Test;
import org.zoxweb.shared.app.AppIDDefault;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Directly exercises {@link AppIDDefault} and the filters wired into it — the same domain
 * (<code>FilterType.DOMAIN</code>) and app-id (<code>AppIDNameFilter</code>) validation
 * that {@link io.xlogistx.nosneak.app.ui.utility.Session#storeAPIKey} relies on when it
 * attaches an AppID to a key. These tests pin the normalization and rejection behavior so
 * a change in the underlying zoxweb filters is caught here rather than surfacing as a
 * confusing failure in the API-key flow.
 *
 * <p>Behavior under test (from the zoxweb sources):</p>
 * <ul>
 *   <li>domain: trimmed, lower-cased, protocol/<code>www.</code> stripped, collapsed to the
 *       registrable domain (last two labels); invalid domains throw
 *       {@link IllegalArgumentException}.</li>
 *   <li>app id: trimmed, lower-cased, letters+digits only; anything else throws.</li>
 *   <li>an app id cannot be set without a domain.</li>
 * </ul>
 */
public class AppIDDefaultTest {

    @Test
    public void validPartsRoundTrip() {
        AppIDDefault app = new AppIDDefault("example.com", "myapp123");
        assertEquals("example.com", app.getDomainID());
        assertEquals("myapp123", app.getAppID());
    }

    @Test
    public void lowerCasesDomainAndAppID() {
        AppIDDefault app = new AppIDDefault("Example.COM", "MyApp123");
        assertEquals("example.com", app.getDomainID(), "domain must be lower-cased");
        assertEquals("myapp123", app.getAppID(), "app id must be lower-cased");
    }

    @Test
    public void trimsSurroundingWhitespace() {
        AppIDDefault app = new AppIDDefault("  example.com  ", "  myapp123  ");
        assertEquals("example.com", app.getDomainID());
        assertEquals("myapp123", app.getAppID());
    }

    @Test
    public void stripsWwwPrefix() {
        AppIDDefault app = new AppIDDefault("www.example.com", "myapp123");
        assertEquals("example.com", app.getDomainID(), "a leading www. must be stripped");
    }

    @Test
    public void collapsesSubdomainToRegistrableDomain() {
        // The domain filter keeps only the last two labels.
        AppIDDefault app = new AppIDDefault("sub.example.com", "myapp123");
        assertEquals("example.com", app.getDomainID(), "a subdomain must collapse to the registrable domain");
    }

    @Test
    public void invalidDomainThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new AppIDDefault("not a domain", "myapp123"),
                "a domain with a space must be rejected");
    }

    @Test
    public void nonAlphanumericAppIDThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new AppIDDefault("example.com", "my-app"),
                "a dash in the app id must be rejected");
    }

    @Test
    public void blankAppIDThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new AppIDDefault("example.com", ""),
                "an empty app id must be rejected");
    }

    @Test
    public void appIDWithoutDomainThrows() {
        // setAppID refuses when no domain is present, so a null domain is unconstructable with an app id.
        assertThrows(IllegalArgumentException.class,
                () -> new AppIDDefault(null, "myapp123"),
                "an app id cannot be set without a domain");
    }

    @Test
    public void createFromDomainAppIDParsesBothParts() {
        AppIDDefault app = AppIDDefault.create("example.com-myapp123");
        assertEquals("example.com", app.getDomainID());
        assertEquals("myapp123", app.getAppID());
    }

    @Test
    public void createFromDomainAppIDMissingSeparatorThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> AppIDDefault.create("nodash"),
                "a domain-app-id without the '-' separator must be rejected");
    }

    @Test
    public void canonicalIDJoinsWithSeparator() {
        AppIDDefault app = new AppIDDefault("example.com", "myapp123");
        assertEquals("example.com-myapp123", app.getDomainAppID(), "canonical form is domain '-' appId");
        assertEquals(app.getDomainAppID(), app.toCanonicalID(), "toCanonicalID must match getDomainAppID");
    }

    @Test
    public void equalsAndHashCodeIgnoreInputCase() {
        AppIDDefault a = new AppIDDefault("example.com", "myapp123");
        AppIDDefault b = new AppIDDefault("Example.COM", "MyApp123");
        assertEquals(a, b, "AppIDs that normalize to the same value must be equal");
        assertEquals(a.hashCode(), b.hashCode(), "equal AppIDs must share a hash code");
    }
}
