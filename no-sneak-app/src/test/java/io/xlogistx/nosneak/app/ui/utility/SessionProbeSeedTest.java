package io.xlogistx.nosneak.app.ui.utility;

import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.app.ui.scan.ProbeSelection;
import io.xlogistx.nosneak.data.ProbeType;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.zoxweb.shared.security.AccessSecurityException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The one-time copy of the bundled probes (2026-11-02, {@code PLAN-single-probe-source.md})
 * through a real encrypted store, the pattern of {@link SessionProbeGroupTest}: a subject's
 * first login copies every bundled definition into their own probes with the origin marked and
 * the marker set; a later login copies nothing, even after a delete; <i>Restore</i> brings back
 * exactly what is missing and never touches a probe the subject changed; each subject is seeded
 * on their own and sees only their own rows.
 */
public class SessionProbeSeedTest {

    private static final String OPERATOR = "operator.local";
    private static final String OPERATOR_PWD = "Operat0r-pass!";
    private static final String OTHER = "other.local";
    private static final String OTHER_PWD = "0ther-Pass!!";
    private static ShiroDSDomainSecurityManager dsm;

    @BeforeAll
    static void createStore() throws Exception {
        System.setProperty("java.awt.headless", "true");
        File dir = new File("target/no-sneak-setup-test/" + UUID.randomUUID().toString().substring(0, 8)).getAbsoluteFile();
        assertTrue(dir.mkdirs() || dir.isDirectory(), "cannot create " + dir);
        NoSneakStore.FirstRun firstRun = new NoSneakStore.FirstRun(OPERATOR, OPERATOR_PWD.toCharArray(), "", null, null);
        dsm = NoSneakStore.create(dir.getPath(), "V4ult-pass!".toCharArray(), firstRun);
        new Session(dsm).registerUsernamePassword(OTHER, OTHER_PWD.toCharArray());
    }

    @AfterAll
    static void closeStore() {
        if (dsm != null) dsm.getDataStore().close();
    }

    private static ProbeType named(List<ProbeType> probes, String name) {
        return probes.stream().filter(p -> name.equals(p.getName())).findFirst().orElse(null);
    }

    @Test
    void theFirstLoginCopiesTheBundleOnceAndRestoreBringsBackOnlyWhatIsMissing() throws Exception {
        int bundled = ProbeDefinitionLoader.BUNDLED.length;
        Session s = new Session(dsm);
        assertFalse(s.probesSeeded(), "signed out: no marker to read");
        assertThrows(AccessSecurityException.class, () -> s.seedBundledProbes(true), "signed out: refused");

        s.loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
        try {
            List<ProbeType> probes = s.getAllProbes();
            assertEquals(bundled, probes.size(), "the first login copied every bundled probe");
            assertTrue(s.probesSeeded(), "and set the marker");
            Set<String> names = new HashSet<>();
            for (ProbeType p : probes) {
                names.add(p.getName());
                assertEquals(s.getSubjectGUID(), p.getSubjectGUID(), "owned by the subject");
                assertTrue(ProbeSelection.isBundledCopy(p), p.getName() + " is marked as a copy");
                assertNotNull(p.getDefinition());
                assertEquals(p.getName(), ProbeDefinitionLoader.parse(p.getDefinition(), p.getName()).getName(), "the copy is the file's own JSON");
            }
            assertTrue(names.contains("ssh") && names.contains("dns") && names.contains("postgres-tls"), names.toString());
            assertEquals(ProbeDefinitionLoader.bundledSource("ssh"), named(probes, "ssh").getDefinition());
            assertNotNull(named(probes, "ssh").getDescription(), "the definition's one-line description comes along");
            assertEquals(0, s.seedBundledProbes(false), "seeded already: nothing to do");

            // the subject makes the library theirs: one edited, one deleted
            ProbeType http = named(probes, "http");
            String edited = http.getDefinition().replace("\"priority\"", "\"description\": \"edited by me\", \"priority\"");
            http.setDefinition(edited);
            s.saveProbe(http);
            s.deleteProbe(named(probes, "ssh"));
            assertEquals(bundled - 1, s.getAllProbes().size());
        } finally {
            s.logout();
        }

        // a later login copies nothing: the delete stands
        s.loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
        try {
            List<ProbeType> probes = s.getAllProbes();
            assertEquals(bundled - 1, probes.size(), "no re-seed on a later login");
            assertNull(named(probes, "ssh"));

            // Restore: exactly the missing one comes back; the edited one is left alone
            assertEquals(1, s.seedBundledProbes(true));
            probes = s.getAllProbes();
            assertEquals(bundled, probes.size());
            ProbeType ssh = named(probes, "ssh");
            assertNotNull(ssh);
            assertTrue(ProbeSelection.isBundledCopy(ssh));
            assertTrue(named(probes, "http").getDefinition().contains("edited by me"), "a changed probe is never overwritten");
            assertEquals(0, s.seedBundledProbes(true), "nothing missing: nothing restored");
            assertEquals(bundled, s.getAllProbes().size());
        } finally {
            s.logout();
        }
    }

    @Test
    void eachSubjectIsSeededOnTheirOwnAndSeesOnlyTheirRows() throws Exception {
        int bundled = ProbeDefinitionLoader.BUNDLED.length;
        Session other = new Session(dsm);
        other.loginUsernamePassword(OTHER, OTHER_PWD.toCharArray());
        try {
            List<ProbeType> mine = other.getAllProbes();
            assertEquals(bundled, mine.size(), "the other subject's own copies, not the operator's");
            for (ProbeType p : mine) assertEquals(other.getSubjectGUID(), p.getSubjectGUID());
            assertTrue(other.probesSeeded());
        } finally {
            other.logout();
        }
        assertFalse(other.probesSeeded(), "signed out again");
    }
}
