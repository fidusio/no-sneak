package io.xlogistx.nosneak.app.ui.utility;

import io.xlogistx.nosneak.app.NoSneakStore;
import io.xlogistx.nosneak.data.ReportContent;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The history page's <i>Delete all</i> (2026-10-25): {@link Session#deleteAllScanResults()} removes
 * every scan of the signed-in subject and reports how many, through the subject view of a real
 * encrypted store; a second call finds nothing; signed out it deletes nothing.
 */
public class SessionScanHistoryTest {

    private static final String OPERATOR = "operator.local";
    private static final String OPERATOR_PWD = "Operat0r-pass!";
    private static ShiroDSDomainSecurityManager dsm;

    @BeforeAll
    static void createStore() throws Exception {
        System.setProperty("java.awt.headless", "true");
        File dir = new File("target/no-sneak-setup-test/" + UUID.randomUUID().toString().substring(0, 8)).getAbsoluteFile();
        assertTrue(dir.mkdirs() || dir.isDirectory(), "cannot create " + dir);
        NoSneakStore.FirstRun firstRun = new NoSneakStore.FirstRun(OPERATOR, OPERATOR_PWD.toCharArray(), "", null, null);
        dsm = NoSneakStore.create(dir.getPath(), "V4ult-pass!".toCharArray(), firstRun);
    }

    @AfterAll
    static void closeStore() {
        if (dsm != null) dsm.getDataStore().close();
    }

    private static ReportContent scan(String name) {
        ReportContent rc = new ReportContent();
        rc.setName(name);
        rc.setDescription("10.0.0.0/24 -p 80");
        rc.setContent("{\"hosts\":[]}");
        return rc;
    }

    @Test
    void deleteAllRemovesEveryScanOfTheSubject() throws Exception {
        Session s = new Session(dsm);
        assertEquals(0, s.deleteAllScanResults(), "signed out: nothing to delete, nothing thrown");

        s.loginUsernamePassword(OPERATOR, OPERATOR_PWD.toCharArray());
        try {
            s.saveScanResult(scan("first"));
            s.saveScanResult(scan("second"));
            s.saveScanResult(scan("third"));
            s.saveScanResult(scan("fourth"));
            s.saveScanResult(scan("fifth"));
            assertEquals(5, s.getAllScanResults().size());

            // a multi-selection delete: two of the five go, three stay
            java.util.List<ReportContent> all = s.getAllScanResults();
            s.deleteScanResults(java.util.List.of(all.get(0), all.get(1)));
            assertEquals(3, s.getAllScanResults().size(), "only the selected ones are deleted");

            assertEquals(3, s.deleteAllScanResults());
            assertTrue(s.getAllScanResults().isEmpty(), "the history is empty");
            assertEquals(0, s.deleteAllScanResults(), "nothing left");
        } finally {
            s.logout();
        }
    }
}
