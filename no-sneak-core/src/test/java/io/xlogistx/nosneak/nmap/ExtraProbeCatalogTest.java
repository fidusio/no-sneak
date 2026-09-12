package io.xlogistx.nosneak.nmap;

import io.xlogistx.nosneak.ProbeChecker;
import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ExtraProbeCatalogTest {

    private static ProbeDefinition extra(String name, int priority, int port) {
        return ProbeDefinitionLoader.parse("""
                {
                  "name": "%s",
                  "service": "custom",
                  "transport": "tcp",
                  "ports": [%d],
                  "priority": %d,
                  "start": "hello",
                  "states": {
                    "hello":  { "action": "connect", "on": { "connected": "finish", "error": "stop" } },
                    "finish": { "action": "done" },
                    "stop":   { "action": "fail" }
                  }
                }
                """.formatted(name, port, priority), name);
    }

    @SuppressWarnings("unchecked")
    private static List<ProbeDefinition> catalogOf(ProbeChecker checker) throws Exception {
        java.lang.reflect.Field f = ProbeChecker.class.getDeclaredField("probes");
        f.setAccessible(true);
        return (List<ProbeDefinition>) f.get(checker);
    }

    private static ProbeChecker build(NMapConfig cfg, ScanReport report) throws Exception {
        // The single buildChecker: a null gate means "unpaced", which is what a catalog test wants.
        Method m = NMapScanner.class.getDeclaredMethod("buildChecker",
                org.zoxweb.server.net.NIOSocket.class, NMapConfig.class, int.class, ScanReport.class,
                ScanGate.class);
        m.setAccessible(true);
        return (ProbeChecker) m.invoke(null, null, cfg, 5, report, null);
    }

    @Test
    public void extraProbeJoinsTheCatalogWhenNoNamesAreRequested() throws Exception {
        NMapConfig cfg = new NMapConfig().target("10.0.0.1");
        cfg.extraProbe(extra("my-echo", 50, 7007));

        List<ProbeDefinition> catalog = catalogOf(build(cfg, new ScanReport()));

        assertEquals(ProbeDefinitionLoader.BUNDLED.length + 1, catalog.size());
        assertTrue(catalog.stream().anyMatch(d -> "my-echo".equals(d.getName())));
    }

    @Test
    public void mergedCatalogStaysSortedByDescendingPriority() throws Exception {
        NMapConfig cfg = new NMapConfig().target("10.0.0.1");
        cfg.extraProbe(extra("top", 999, 7007));
        cfg.extraProbe(extra("bottom", -1, 7008));

        List<ProbeDefinition> catalog = catalogOf(build(cfg, new ScanReport()));

        assertEquals("top", catalog.getFirst().getName());
        assertEquals("bottom", catalog.getLast().getName());
        for (int i = 1; i < catalog.size(); i++) {
            assertTrue(catalog.get(i - 1).getPriority() >= catalog.get(i).getPriority(),
                    "catalog out of priority order at " + i);
        }
    }

    @Test
    public void anExtraProbeCanBeSelectedByName() throws Exception {
        NMapConfig cfg = new NMapConfig().target("10.0.0.1").probe("my-echo");
        cfg.extraProbe(extra("my-echo", 50, 7007));
        ScanReport report = new ScanReport();

        List<ProbeDefinition> subset = catalogOf(build(cfg, report));

        assertEquals(1, subset.size());
        assertEquals("my-echo", subset.getFirst().getName());
        assertTrue(report.warnings.isEmpty(), report.warnings.toString());
    }

    @Test
    public void aBundledProbeIsStillSelectableAlongsideAnExtra() throws Exception {
        NMapConfig cfg = new NMapConfig().target("10.0.0.1").probe("ssh").probe("my-echo");
        cfg.extraProbe(extra("my-echo", 50, 7007));
        ScanReport report = new ScanReport();

        List<ProbeDefinition> subset = catalogOf(build(cfg, report));

        assertEquals(2, subset.size());
        assertTrue(subset.stream().anyMatch(d -> "ssh".equals(d.getName())));
        assertTrue(subset.stream().anyMatch(d -> "my-echo".equals(d.getName())));
        assertTrue(report.warnings.isEmpty(), report.warnings.toString());
    }

    /** A subject-authored probe that reuses a bundled name replaces it — one definition per name. */
    @Test
    public void aStoredProbeShadowsTheBundledProbeOfTheSameName() throws Exception {
        NMapConfig cfg = new NMapConfig().target("10.0.0.1");
        cfg.extraProbe(extra("ssh", 5, 2222));
        ScanReport report = new ScanReport();

        List<ProbeDefinition> catalog = catalogOf(build(cfg, report));

        assertEquals(ProbeDefinitionLoader.BUNDLED.length, catalog.size(), "replaced, not added");
        List<ProbeDefinition> named = catalog.stream().filter(d -> "ssh".equals(d.getName())).toList();
        assertEquals(1, named.size());
        assertEquals("custom", named.getFirst().getService(), "the stored definition won");
        assertEquals(5, named.getFirst().getPriority());
        assertTrue(report.warnings.stream().anyMatch(w -> w.contains("ssh") && w.contains("shadows")),
                report.warnings.toString());

        // Selecting it by name yields exactly one probe, never both.
        NMapConfig byName = new NMapConfig().target("10.0.0.1").probe("ssh");
        byName.extraProbe(extra("ssh", 5, 2222));
        assertEquals(1, catalogOf(build(byName, new ScanReport())).size());
    }

    /** Two stored probes with one name: the first is kept, the second reported. */
    @Test
    public void aDuplicateStoredProbeIsIgnoredAndReported() throws Exception {
        NMapConfig cfg = new NMapConfig().target("10.0.0.1");
        cfg.extraProbe(extra("my-echo", 50, 7007));
        cfg.extraProbe(extra("my-echo", 90, 7008));
        ScanReport report = new ScanReport();

        List<ProbeDefinition> catalog = catalogOf(build(cfg, report));

        List<ProbeDefinition> named = catalog.stream().filter(d -> "my-echo".equals(d.getName())).toList();
        assertEquals(1, named.size());
        assertEquals(50, named.getFirst().getPriority(), "the first definition is the one used");
        assertTrue(report.warnings.stream().anyMatch(w -> w.contains("duplicate stored probe 'my-echo'")),
                report.warnings.toString());
    }

    @Test
    public void anUnknownNameStillWarnsWithExtrasPresent() throws Exception {
        NMapConfig cfg = new NMapConfig().target("10.0.0.1").probe("my-echo").probe("nope");
        cfg.extraProbe(extra("my-echo", 50, 7007));
        ScanReport report = new ScanReport();

        List<ProbeDefinition> subset = catalogOf(build(cfg, report));

        assertEquals(1, subset.size());
        assertTrue(report.warnings.stream().anyMatch(w -> w.contains("nope")), report.warnings.toString());
        assertFalse(report.warnings.stream().anyMatch(w -> w.contains("my-echo")), report.warnings.toString());
    }
}