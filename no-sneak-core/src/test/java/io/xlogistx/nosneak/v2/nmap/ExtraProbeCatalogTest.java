package io.xlogistx.nosneak.v2.nmap;

import io.xlogistx.nosneak.v2.ProbeChecker;
import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeDefinitionLoader;
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
        Method m = NMapScanner.class.getDeclaredMethod("buildChecker",
                org.zoxweb.server.net.NIOSocket.class, NMapConfig.class, int.class, ScanReport.class);
        m.setAccessible(true);
        return (ProbeChecker) m.invoke(null, null, cfg, 5, report);
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