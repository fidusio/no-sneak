package io.xlogistx.nosneak.app;

import io.xlogistx.nosneak.app.ui.utility.Session;

import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The session's listener plumbing behind the theme switch (2026-11-02): {@code replayAuthenticated}
 * fires the authenticated event again, as true, only while signed in; {@code removeListeners}
 * drops every listener so the panels of a replaced shell stop hearing the session, and one
 * registered afterwards hears the replay alone.
 */
class SessionListenersTest {

    private static Session signedIn() {
        ShiroDSDomainSecurityManager dsm = TestSecurity.newManager();
        TestSecurity.createUser(dsm, "theme-user", "Password1!");
        Session s = new Session(dsm);
        s.loginUsernamePassword("theme-user", "Password1!".toCharArray());
        return s;
    }

    @Test
    void theReplayFiresTrueOnlyWhileSignedIn() {
        Session s = signedIn();
        List<Object> seen = new ArrayList<>();
        s.onAuthChange(e -> seen.add(e.getNewValue()));

        s.replayAuthenticated();
        assertEquals(List.of(true), seen, "signed in: the event again, as true");

        s.logout();
        assertEquals(List.of(true, false), seen, "the logout itself");
        s.replayAuthenticated();
        assertEquals(List.of(true, false), seen, "signed out: nothing to replay");
    }

    @Test
    void removingTheListenersLeavesOnlyThoseRegisteredAfterwards() {
        Session s = signedIn();
        List<String> seen = new ArrayList<>();
        s.onAuthChange(_ -> seen.add("old auth"));
        s.onCredentialsChange(_ -> seen.add("old credentials"));
        s.onMacVendorsChange(_ -> seen.add("old vendors"));

        s.removeListeners();
        s.onAuthChange(_ -> seen.add("new auth"));
        s.replayAuthenticated();
        assertEquals(List.of("new auth"), seen, "the old shell's listeners are gone, the new one hears the replay");

        s.logout();
        assertEquals(List.of("new auth", "new auth"), seen, "and the logout");
    }
}
