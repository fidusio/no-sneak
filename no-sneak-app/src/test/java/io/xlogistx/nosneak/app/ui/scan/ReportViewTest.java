package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.nosneak.nmap.NMapConfig;
import io.xlogistx.nosneak.nmap.PortState;
import io.xlogistx.nosneak.nmap.ScanReport;
import io.xlogistx.nosneak.nmap.output.OutputFormat;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The report model reads the engine's own JSON: hosts, ports, the per-port grade / PQC / trust the
 * engine wrote, and the derived counts and host posture the result tables show.
 */
public class ReportViewTest {

    private static final String SAMPLE = """
            {
              "scanner": "XNMap", "startTimeMs": 1761297242000, "startTime": "2026-10-24T09:14:02Z",
              "durationMs": 6210, "durationSec": 6.21, "targets": 3, "up": 2, "hostsDown": 1,
              "command": "10.0.0.0/24 -p 1-1024 -sV", "cancelled": false,
              "hosts": [
                {"host": "10.0.0.12", "ip": "10.0.0.12", "hostname": "nas.lan", "up": true, "reason": "arp-reply",
                 "mac": "00:11:22:33:44:55", "latencyMs": 1,
                 "portStats": {"open": 2, "closed": 1022, "filtered": 0},
                 "ports": [
                   {"port": 22, "protocol": "tcp", "state": "open", "reason": "connected", "rttMs": 2,
                    "service": "ssh", "version": "OpenSSH 9.8", "probe": {"probe": "ssh-version", "tls-state": "NONE"}},
                   {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.27",
                    "tls": "DIRECT_TLS", "pqc": "PQC", "certValidity": "VALID", "certChainTrust": "TRUSTED",
                    "grade": "grade=A pqc=PQC_READY trust=TRUSTED advisories=[CBC suites accepted: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA; prefer AEAD]",
                    "probe": {"probe": "https-scan", "tls-version": "TLSv1.3", "cipher-suite": "TLS_AES_256_GCM_SHA384",
                              "key-exchange-group": "X25519MLKEM768", "cert-subject": "CN=nas.lan", "cert-issuer": "CN=Internal CA",
                              "cert-not-after": "2026-12-04T00:00:00Z", "supported-groups": ["X25519MLKEM768", "X25519"],
                              "supported-protocol-versions": ["TLSv1.3", "TLSv1.2"]}}
                 ]},
                {"host": "10.0.0.23", "ip": "10.0.0.23", "up": true,
                 "ports": [
                   {"port": 631, "protocol": "tcp", "state": "open", "service": "ipp", "tls": "DIRECT_TLS", "pqc": "NOT_READY",
                    "certValidity": "EXPIRED", "grade": "grade=D pqc=CLASSICAL_ONLY trust=EXPIRED",
                    "probe": {"probe": "tls-scan", "tls-version": "TLSv1.2", "key-exchange-algorithm": "RSA"}},
                   {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                 ]},
                {"host": "10.0.0.9", "up": false, "ports": []}
              ]
            }
            """;

    @Test
    void readsHostsPortsAndTheEngineGrades() {
        ReportView.Report r = ReportView.parse(SAMPLE);
        assertEquals("10.0.0.0/24 -p 1-1024 -sV", r.command());
        assertEquals(6210, r.durationMs());
        assertEquals("6.2 s", r.durationLabel());
        assertEquals(3, r.hosts().size());
        assertEquals(2, r.upHosts().size());
        assertEquals(4, r.openPortCount());
        assertEquals(2, r.tlsEndpointCount());
        assertEquals(1, r.pqcReadyCount());

        ReportView.Host nas = r.hosts().get(0);
        assertEquals("10.0.0.12", nas.address());
        assertEquals("nas.lan", nas.hostname());
        assertEquals("00:11:22:33:44:55", nas.mac());
        assertEquals("ssh, https", nas.serviceList());
        ReportView.Port https = nas.ports().get(1);
        assertTrue(https.hasTls());
        assertEquals("A", https.gradeLetter());
        assertEquals("TRUSTED", https.trust());
        assertEquals(1, https.advisories().size());
        assertTrue(https.advisories().get(0).startsWith("CBC suites accepted"));
        assertEquals("TLS 1.3 · X25519MLKEM768", https.tlsSummary());
        assertEquals("nginx 1.27 · https-scan", https.detail());
        assertEquals("443/tcp", https.portLabel());
        assertEquals(List.of("X25519MLKEM768", "X25519"), https.supportedGroups());
        assertFalse(nas.ports().get(0).hasTls());
        assertEquals("OpenSSH 9.8 · ssh-version", nas.ports().get(0).detail());
    }

    @Test
    void hostPostureIsTheWorstTlsPortWithItsPqcWord() {
        ReportView.Report r = ReportView.parse(SAMPLE);
        ReportView.Posture nas = r.hosts().get(0).posture();
        assertEquals("A", nas.letter());
        assertEquals("A · Hybrid PQC", nas.label());
        assertEquals(ReportView.Tone.OK, nas.tone());

        ReportView.Posture printer = r.hosts().get(1).posture();
        assertEquals("D", printer.letter());
        assertEquals("D · Not ready", printer.label());
        assertEquals(ReportView.Tone.DANGER, printer.tone());
        assertEquals(631, r.hosts().get(1).worstTlsPort().port());

        ReportView.Posture down = r.hosts().get(2).posture();
        assertFalse(down.hasTls());
        assertEquals("No TLS", down.label());
        assertEquals(ReportView.Tone.NEUTRAL, down.tone());
    }

    @Test
    void readsWhatTheEngineRendersForReal() {
        ScanReport report = new ScanReport();
        report.config = new NMapConfig().target("10.0.0.1");
        report.commandLine = "10.0.0.1 -p 22";
        report.startTimeMs = 1000;
        report.endTimeMs = 3500;
        ScanReport.HostReport h = new ScanReport.HostReport("10.0.0.1");
        h.ip = "10.0.0.1";
        h.up = true;
        h.ports.add(new ScanReport.PortReport(22, PortState.OPEN));
        h.ports.add(new ScanReport.PortReport(23, PortState.CLOSED));
        report.hosts.add(h);
        String json = OutputFormat.formatter(OutputFormat.JSON).render(report);

        ReportView.Report r = ReportView.parse(json);
        assertEquals("10.0.0.1 -p 22", r.command());
        assertEquals(2500, r.durationMs());
        assertEquals(1, r.hosts().size());
        assertTrue(r.hosts().get(0).up());
        assertEquals(1, r.openPortCount());
        assertEquals("ssh", r.hosts().get(0).openPorts().get(0).service(), "well-known name from the engine");
        assertEquals("No TLS", r.hosts().get(0).posture().label());
    }

    @Test
    void refusesWhatIsNotAReport() {
        assertThrows(IllegalArgumentException.class, () -> ReportView.parse("not json"));
        assertThrows(IllegalArgumentException.class, () -> ReportView.parse("[1,2]"));
        ReportView.Report empty = ReportView.parse("{}");
        assertTrue(empty.hosts().isEmpty());
        assertEquals(0, empty.openPortCount());
    }
}
