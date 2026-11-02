package io.xlogistx.nosneak.app.ui.utility;

import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.data.ProbeGroup;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Probe groups through a real encrypted store (2026-11-01, the pattern of
 * {@link SessionScanHistoryTest}): save inserts with the owner and a GUID, a second save of the
 * same row updates it, delete removes it, the list is the signed-in subject's own and empty when
 * signed out.
 */
public class SessionProbeGroupTest {

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

    private static ProbeGroup group(String name, String csv) {
        ProbeGroup g = new ProbeGroup();
        g.setName(name);
        g.setDescription("desc of " + name);
        g.setProbes(csv);
        return g;
    }

    @Test
    void saveUpdateDeleteAndTheListIsSubjectScoped() throws Exception {
        Session s = new Session(dsm);
        assertTrue(s.getAllProbeGroups().isEmpty(), "signed out: no groups, nothing thrown");

        s.loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
        try {
            ProbeGroup web = s.saveProbeGroup(group("web", "ssh, https-pqc"));
            assertNotNull(web.getGUID(), "insert assigns a GUID");
            assertEquals(s.getSubjectGUID(), web.getSubjectGUID(), "insert stamps the owner");
            s.saveProbeGroup(group("mail", "smtp-starttls-pqc"));

            List<ProbeGroup> all = s.getAllProbeGroups();
            assertEquals(2, all.size());
            ProbeGroup read = s.getProbeGroup(web.getGUID());
            assertNotNull(read);
            assertEquals("web", read.getName());
            assertEquals("desc of web", read.getDescription());
            assertEquals(List.of("ssh", "https-pqc"), List.copyOf(read.getProbes()), "the set round-trips in order");

            // a second save of the same row updates it: still two groups, the content changed
            read.setProbes(Set.of("ssh"));
            read.setDescription("just ssh");
            ProbeGroup updated = s.saveProbeGroup(read);
            assertEquals(web.getGUID(), updated.getGUID());
            assertTrue(updated.getLastTimeUpdated() > 0, "update stamps lastTimeUpdated");
            assertEquals(2, s.getAllProbeGroups().size(), "an edit does not duplicate the row");
            assertEquals(Set.of("ssh"), s.getProbeGroup(web.getGUID()).getProbes());
            assertEquals("just ssh", s.getProbeGroup(web.getGUID()).getDescription());

            s.deleteProbeGroup(updated);
            assertEquals(1, s.getAllProbeGroups().size());
            assertNull(s.getProbeGroup(web.getGUID()), "deleted: not found");
        } finally {
            s.logout();
        }
        assertTrue(s.getAllProbeGroups().isEmpty(), "signed out again: nothing");

        // another subject sees none of the operator's groups and keeps its own
        Session other = new Session(dsm);
        other.loginUsernamePassword(OTHER, OTHER_PWD.toCharArray());
        try {
            assertTrue(other.getAllProbeGroups().isEmpty(), "the operator's group is not the other subject's");
            other.saveProbeGroup(group("mine", "ssh"));
            assertEquals(1, other.getAllProbeGroups().size());
        } finally {
            other.logout();
        }
        s.loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
        try {
            List<ProbeGroup> mine = s.getAllProbeGroups();
            assertEquals(1, mine.size());
            assertEquals("mail", mine.getFirst().getName());
        } finally {
            s.logout();
        }
    }
}
