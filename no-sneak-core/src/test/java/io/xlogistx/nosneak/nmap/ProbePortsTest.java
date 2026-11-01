package io.xlogistx.nosneak.nmap;

import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The ports a scan covers when none are typed (2026-10-31, the maintainer: "if the ports are not
 * set and probes were selected we scan the probe default port per probe"): the named probes'
 * declared ports, per transport; typed ports always win; a set that declares none falls back to
 * the default list with a warning. Pure — {@link NMapScanner#resolvePorts} and
 * {@link NMap#probePorts} open no socket.
 */
public class ProbePortsTest {

    private static ProbeDefinition extra(String name, String transport, String ports) {
        return ProbeDefinitionLoader.parse("""
                {
                  "name": "%s",
                  "service": "custom",
                  "transport": "%s",
                  "ports": %s,
                  "priority": 50,
                  "start": "hello",
                  "states": {
                    "hello":  { "action": "connect", "on": { "connected": "finish", "error": "stop" } },
                    "finish": { "action": "done" },
                    "stop":   { "action": "fail" }
                  }
                }
                """.formatted(name, transport, ports), name);
    }

    private static NMap.PortSpec resolve(NMapConfig cfg, ScanReport report) {
        List<ProbeDefinition> catalog = cfg.probeScan ? NMapScanner.selectedCatalog(cfg, report) : null;
        return NMapScanner.resolvePorts(cfg, catalog, report);
    }

    @Test
    public void namedBundledProbesScanTheirDeclaredPortsOnly() {
        NMapConfig cfg = new NMapConfig().probeScan(true).probe("ssh").probe("https-pqc");
        ScanReport report = new ScanReport();
        NMap.PortSpec spec = resolve(cfg, report);
        assertArrayEquals(new int[]{22, 443, 2222, 8443}, spec.tcp(), "sorted union of ssh and https-pqc");
        assertArrayEquals(new int[0], spec.udp());
        assertTrue(report.warnings.isEmpty(), report.warnings.toString());
    }

    @Test
    public void aUdpProbePutsItsPortsOnTheUdpSide() {
        NMapConfig cfg = new NMapConfig().probeScan(true).probe("dns");
        NMap.PortSpec spec = resolve(cfg, new ScanReport());
        assertArrayEquals(new int[0], spec.tcp(), "no TCP probe named, no TCP port");
        assertArrayEquals(new int[]{53}, spec.udp());
    }

    @Test
    public void derivedUdpPortsJoinTheOnesAlreadyNamed() {
        NMapConfig cfg = new NMapConfig().udpPorts(new int[]{161}).probeScan(true).probe("dns");
        NMap.PortSpec spec = resolve(cfg, new ScanReport());
        assertArrayEquals(new int[]{53, 161}, spec.udp());
    }

    @Test
    public void aStoredProbeCountsLikeABundledOne() {
        NMapConfig cfg = new NMapConfig().probeScan(true)
                .extraProbe(extra("my-redis", "tcp", "[6379, 6380]")).probe("my-redis");
        NMap.PortSpec spec = resolve(cfg, new ScanReport());
        assertArrayEquals(new int[]{6379, 6380}, spec.tcp());
    }

    @Test
    public void typedPortsWinOverTheProbes() {
        NMapConfig cfg = new NMapConfig().ports(new int[]{80}).probeScan(true).probe("ssh");
        NMap.PortSpec spec = resolve(cfg, new ScanReport());
        assertArrayEquals(new int[]{80}, spec.tcp());
    }

    @Test
    public void noProbeNamedMeansTheDefaultList() {
        ScanReport report = new ScanReport();
        assertArrayEquals(NMap.DEFAULT_PORTS, resolve(new NMapConfig(), report).tcp());
        // a bare -sV (whole catalog) is not a named set either
        assertArrayEquals(NMap.DEFAULT_PORTS, resolve(new NMapConfig().probeScan(true), report).tcp());
        assertTrue(report.warnings.isEmpty(), report.warnings.toString());
    }

    @Test
    public void probesWithoutDeclaredPortsFallBackToTheDefaultListWithAWarning() {
        NMapConfig cfg = new NMapConfig().probeScan(true).probe("tls-scan");
        ScanReport report = new ScanReport();
        NMap.PortSpec spec = resolve(cfg, report);
        assertArrayEquals(NMap.DEFAULT_PORTS, spec.tcp());
        assertEquals(1, report.warnings.size(), report.warnings.toString());
        assertTrue(report.warnings.get(0).contains("declare no ports"), report.warnings.get(0));
    }

    @Test
    public void aSetThatMatchesNothingProbesNothingAndScansTheDefaultList() {
        NMapConfig cfg = new NMapConfig().probeScan(true).probe("no-such-probe");
        ScanReport report = new ScanReport();
        NMap.PortSpec spec = resolve(cfg, report);
        assertArrayEquals(NMap.DEFAULT_PORTS, spec.tcp());
        assertTrue(report.warnings.stream().anyMatch(w -> w.contains("nothing probed")), report.warnings.toString());
    }

    @Test
    public void probePortsIsASortedUnionPerTransport() {
        NMap.PortSpec spec = NMap.probePorts(List.of(
                extra("a", "tcp", "[8443, 443]"),
                extra("b", "tcp", "[443, 22]"),
                extra("c", "udp", "[161, 53]"),
                extra("d", "tcp", "[]")));
        assertArrayEquals(new int[]{22, 443, 8443}, spec.tcp());
        assertArrayEquals(new int[]{53, 161}, spec.udp());
        assertArrayEquals(new int[0], NMap.probePorts(null).tcp());
        assertArrayEquals(new int[0], NMap.probePorts(List.of()).udp());
    }
}
