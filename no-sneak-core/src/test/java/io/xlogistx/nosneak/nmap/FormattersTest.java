package io.xlogistx.nosneak.nmap;

import io.xlogistx.nosneak.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.nmap.ScanReport.RenderSelection;
import io.xlogistx.nosneak.nmap.output.OutputFormat;
import io.xlogistx.nosneak.nmap.output.OutputFormatter;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The five renderers are pure functions of a {@link ScanReport}; this builds one by hand and
 * pins what wave 1 populated and wave 2 renders: the per-port {@code reason}, the round-trip
 * time when measured, the one shared rule behind {@code --open}, down hosts in every format,
 * and the nmap run metadata (DOCTYPE, scaninfo, host times, PTR hostnames, runstats, grepable
 * header/footer, JSON times and per-host port stats).
 */
public class FormattersTest {

    private static PortReport port(int n, PortState s, String reason, long rtt, String banner) {
        PortReport p = new PortReport(n, s);
        p.reason = reason;
        p.rttMs = rtt;
        p.banner = banner;
        return p;
    }

    /** Two hosts: one with open, closed and filtered ports; one down. */
    private static ScanReport report(boolean openOnly) {
        ScanReport r = new ScanReport();
        r.startTimeMs = 1_000;
        r.endTimeMs = 3_500;
        r.commandLine = "xnmap -p 22,80,443,8080,9000 10.0.0.9";
        r.config = new NMapConfig().target("10.0.0.9").openOnly(openOnly);

        HostReport up = new HostReport("10.0.0.9");
        up.ip = "10.0.0.9";
        up.up = true;
        up.reason = "arp-reply";
        up.mac = "b8:27:eb:30:40:d7";
        up.ports.add(port(22, PortState.OPEN, "connected", 12, "SSH-2.0-OpenSSH_8.2p1"));
        up.ports.add(port(443, PortState.OPEN, "connected", 25, null));
        up.ports.add(port(80, PortState.CLOSED, "conn-refused", -1, null));
        up.ports.add(port(8080, PortState.FILTERED, "timeout", -1, null));
        up.ports.add(port(9000, PortState.FILTERED, "error:SocketException", -1, null));
        r.hosts.add(up);

        HostReport down = new HostReport("10.0.0.250");
        down.up = false;
        down.reason = "no-response";
        r.hosts.add(down);
        return r;
    }

    /** {@code getValue} is generic; going through Object keeps javac from picking the char[] overload of String.valueOf. */
    private static String str(org.zoxweb.shared.util.NVGenericMap m, String key) {
        Object v = m.getValue(key);
        return v == null ? null : v.toString();
    }

    private static String render(OutputFormat f, ScanReport r) {
        OutputFormatter fmt = OutputFormat.formatter(f);
        assertEquals(f, fmt.format());
        return fmt.render(r);
    }

    private static org.zoxweb.shared.util.NVGenericMap json(ScanReport r) {
        return org.zoxweb.server.util.GSONUtil.fromJSONGenericMap(
                render(OutputFormat.JSON, r).getBytes(StandardCharsets.UTF_8));
    }

    // ---- the shared selection rule ----

    @Test
    public void smallNonOpenStatesAreListedByDefault() {
        HostReport h = report(false).hosts.getFirst();
        RenderSelection sel = h.portsToRender(new NMapConfig());
        assertEquals(5, sel.shown.size());
        assertTrue(sel.hidden.isEmpty());
        assertNull(sel.notShown());
    }

    @Test
    public void openOnlyHidesEveryNonOpenPortButKeepsTheCounts() {
        HostReport h = report(true).hosts.getFirst();
        RenderSelection sel = h.portsToRender(new NMapConfig().openOnly(true));
        assertEquals(2, sel.shown.size());
        assertTrue(sel.shown.stream().allMatch(p -> p.state.isPotentiallyOpen()));
        assertEquals(1, sel.hidden(PortState.CLOSED));
        assertEquals(2, sel.hidden(PortState.FILTERED));
        assertEquals("1 closed, 2 filtered", sel.notShown());
    }

    @Test
    public void aStateWithMoreThanTheThresholdCollapsesIntoACount() {
        HostReport h = new HostReport("h");
        h.up = true;
        h.ports.add(port(443, PortState.OPEN, "connected", 3, null));
        for (int i = 0; i < RenderSelection.COLLAPSE_THRESHOLD + 1; i++) {
            h.ports.add(port(1000 + i, PortState.CLOSED, "conn-refused", -1, null));
        }
        h.ports.add(port(9000, PortState.FILTERED, "timeout", -1, null));
        RenderSelection sel = h.portsToRender(null);
        assertEquals(2, sel.shown.size(), "open + the one filtered port stay listed");
        assertEquals(RenderSelection.COLLAPSE_THRESHOLD + 1, sel.hidden(PortState.CLOSED));
        assertEquals("11 closed, 0 filtered", sel.notShown());
    }

    @Test
    public void aNullConfigMeansNotOpenOnly() {
        HostReport h = report(false).hosts.getFirst();
        assertEquals(5, h.portsToRender(null).shown.size());
    }

    // ---- reason and RTT in every format ----

    @Test
    public void normalListsReasonAndRttPerPort() {
        String out = render(OutputFormat.NORMAL, report(false));
        assertTrue(out.contains("REASON") && out.contains("RTT"), out);
        assertTrue(out.contains("443/tcp") && out.contains("connected") && out.contains("25 ms"), out);
        assertTrue(out.contains("80/tcp") && out.contains("conn-refused"), out);
        assertTrue(out.contains("error:SocketException"), out);
        assertTrue(out.contains("SSH-2.0-OpenSSH_8.2p1"), "banner still rendered");
        assertFalse(out.contains("Not shown"), "nothing collapsed at five ports");
        assertFalse(out.contains("10.0.0.250 is up"));
    }

    @Test
    public void normalUnderOpenOnlyHidesClosedAndFilteredButKeepsTheCounts() {
        String out = render(OutputFormat.NORMAL, report(true));
        assertTrue(out.contains("Not shown: 1 closed, 2 filtered"), out);
        assertFalse(out.contains("80/tcp"), out);
        assertFalse(out.contains("8080/tcp"), out);
        assertTrue(out.contains("443/tcp"), out);
    }

    // ---- down hosts (v1 printed them; v2 skipped them) ----

    @Test
    public void normalPrintsOneLinePerDownHostWithItsReason() {
        String out = render(OutputFormat.NORMAL, report(false));
        assertTrue(out.contains("Host 10.0.0.250 is down (no-response)\n"), out);
        assertTrue(out.indexOf("10.0.0.9 is up") < out.indexOf("10.0.0.250 is down"), "report order is target order");
    }

    @Test
    public void normalVerboseAddsARunHeaderAndScannedCountsButWarningsShowRegardless() {
        ScanReport r = report(false);
        r.warnings.add("ICMP discovery unavailable: no privilege");
        String quiet = render(OutputFormat.NORMAL, r);
        assertFalse(quiet.contains("Starting NoSneak"), quiet);
        assertFalse(quiet.contains("Scanned:"), quiet);
        assertTrue(quiet.contains("Warning: ICMP discovery unavailable: no privilege"), "warnings are never hidden");

        r.config.verbose(true);
        String verbose = render(OutputFormat.NORMAL, r);
        assertTrue(verbose.startsWith("Starting NoSneak " + ScanReport.VERSION + " at "), verbose);
        assertTrue(verbose.contains(" as: xnmap -p 22,80,443,8080,9000 10.0.0.9\n"), verbose);
        assertTrue(verbose.contains("  Scanned: 5 tcp, 0 udp port(s)\n"), verbose);
        assertTrue(verbose.contains("Warning: ICMP discovery unavailable: no privilege"), verbose);
    }

    @Test
    public void normalPrintsTheReverseDnsName() {
        ScanReport r = report(false);
        r.hosts.getFirst().hostname = "web.lan";
        String out = render(OutputFormat.NORMAL, r);
        assertTrue(out.contains("  Hostname: web.lan\n"), out);
    }

    /**
     * JSON is the house serialiser over {@link ScanReport#toNVGenericMap()}, so the assertions
     * parse it back rather than string-match a layout: the shape is the contract, not the
     * whitespace.
     */
    @Test
    public void jsonCarriesReasonAndOnlyMeasuredRtt() {
        String out = render(OutputFormat.JSON, report(false));
        org.zoxweb.shared.util.NVGenericMap root =
                org.zoxweb.server.util.GSONUtil.fromJSONGenericMap(out.getBytes(StandardCharsets.UTF_8));
        assertEquals("XNMap", root.getValue("scanner"));
        java.util.List<org.zoxweb.shared.util.NVGenericMap> hosts =
                ((org.zoxweb.shared.util.NVGenericMapList) root.get("hosts")).getValue();
        assertEquals(2, hosts.size());
        org.zoxweb.shared.util.NVGenericMap h0 = hosts.get(0);
        java.util.List<org.zoxweb.shared.util.NVGenericMap> ports =
                ((org.zoxweb.shared.util.NVGenericMapList) h0.get("ports")).getValue();
        org.zoxweb.shared.util.NVGenericMap p443 = ports.stream()
                .filter(p -> "443".equals(str(p, "port"))).findFirst().orElseThrow();
        assertEquals("open", p443.getValue("state"));
        assertEquals("connected", p443.getValue("reason"));
        assertEquals("25", str(p443, "rttMs"));
        org.zoxweb.shared.util.NVGenericMap p80 = ports.stream()
                .filter(p -> "80".equals(str(p, "port"))).findFirst().orElseThrow();
        assertEquals("closed", p80.getValue("state"));
        assertEquals("conn-refused", p80.getValue("reason"));
        assertTrue(p80.get("rttMs") == null, "an unmeasured RTT is absent, never -1");
        assertTrue(h0.get("notShown") == null, "nothing hidden");
        assertFalse(out.contains("-1"), out);
    }

    @Test
    public void jsonUnderOpenOnlyNamesWhatWasHidden() {
        String out = render(OutputFormat.JSON, report(true));
        org.zoxweb.shared.util.NVGenericMap root =
                org.zoxweb.server.util.GSONUtil.fromJSONGenericMap(out.getBytes(StandardCharsets.UTF_8));
        org.zoxweb.shared.util.NVGenericMap h0 =
                ((org.zoxweb.shared.util.NVGenericMapList) root.get("hosts")).getValue().get(0);
        org.zoxweb.shared.util.NVGenericMap hidden = (org.zoxweb.shared.util.NVGenericMap) h0.get("notShown");
        assertEquals("1", str(hidden, "closed"));
        assertEquals("2", str(hidden, "filtered"));
        java.util.List<org.zoxweb.shared.util.NVGenericMap> ports =
                ((org.zoxweb.shared.util.NVGenericMapList) h0.get("ports")).getValue();
        assertTrue(ports.stream().noneMatch(p -> "80".equals(str(p, "port"))), out);
        assertTrue(ports.stream().anyMatch(p -> "22".equals(str(p, "port"))), out);
    }

    @Test
    public void jsonCarriesIsoTimesDurationHostsDownAndPerHostPortStats() {
        ScanReport r = report(false);
        r.hosts.getFirst().startTimeMs = 1_000;
        r.hosts.getFirst().endTimeMs = 3_000;
        org.zoxweb.shared.util.NVGenericMap root = json(r);
        assertEquals("1970-01-01T00:00:01Z", str(root, "startTime"), "ISO-8601, UTC, zone-independent");
        assertEquals("1970-01-01T00:00:03.500Z", str(root, "endTime"));
        assertEquals(2.5, Double.parseDouble(str(root, "durationSec")), 1e-9);
        assertEquals("2500", str(root, "durationMs"));
        assertEquals("1", str(root, "hostsDown"));
        assertEquals("1", str(root, "up"));

        java.util.List<org.zoxweb.shared.util.NVGenericMap> hosts =
                ((org.zoxweb.shared.util.NVGenericMapList) root.get("hosts")).getValue();
        org.zoxweb.shared.util.NVGenericMap h0 = hosts.get(0);
        org.zoxweb.shared.util.NVGenericMap stats = (org.zoxweb.shared.util.NVGenericMap) h0.get("portStats");
        assertEquals("2", str(stats, "open"));
        assertEquals("1", str(stats, "closed"));
        assertEquals("2", str(stats, "filtered"));
        assertEquals("1970-01-01T00:00:01Z", str(h0, "startTime"));
        assertEquals("1970-01-01T00:00:03Z", str(h0, "endTime"));

        org.zoxweb.shared.util.NVGenericMap h1 = hosts.get(1);
        org.zoxweb.shared.util.NVGenericMap down = (org.zoxweb.shared.util.NVGenericMap) h1.get("portStats");
        assertEquals("0", str(down, "open"));
        assertTrue(h1.get("startTime") == null, "an unset host time is absent, not 1970");
        assertTrue(h1.get("hostname") == null && h1.get("osGuess") == null, "no never-assigned fields");
    }

    @Test
    public void xmlKeepsNmapStateShapeAndAddsRttAndExtraports() {
        String out = render(OutputFormat.XML, report(false));
        assertTrue(out.contains("<port protocol=\"tcp\" portid=\"443\" rttms=\"25\">"), out);
        assertTrue(out.contains("<state state=\"open\" reason=\"connected\"/>"), out);
        assertTrue(out.contains("<port protocol=\"tcp\" portid=\"80\">"), "no rttms when unmeasured");
        assertTrue(out.contains("<state state=\"closed\" reason=\"conn-refused\"/>"), out);
        assertFalse(out.contains("extraports"), out);

        String open = render(OutputFormat.XML, report(true));
        assertTrue(open.contains("<extraports state=\"closed\" count=\"1\"/>"), open);
        assertTrue(open.contains("<extraports state=\"filtered\" count=\"2\"/>"), open);
        assertFalse(open.contains("portid=\"80\""), open);
    }

    @Test
    public void xmlCarriesTheRunMetadataNmapConsumersExpect() {
        ScanReport r = report(false);
        HostReport up = r.hosts.getFirst();
        up.hostname = "web.lan";
        up.startTimeMs = 1_000;
        up.endTimeMs = 3_000;
        String out = render(OutputFormat.XML, r);
        assertTrue(out.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE nmaprun>\n<nmaprun scanner=\"nosneak\""), out);
        assertTrue(out.contains(" args=\"xnmap -p 22,80,443,8080,9000 10.0.0.9\" start=\"1\" startstr=\""), out);
        assertTrue(out.contains(" version=\"" + ScanReport.VERSION + "\">"), out);
        assertTrue(out.contains("<scaninfo type=\"connect\" protocol=\"tcp\" numservices=\"1024\" services=\"1-1024\"/>"),
                "a config without -p scans the default 1-1024: " + out);
        assertFalse(out.contains("protocol=\"udp\""), "no UDP ports were named");
        assertTrue(out.contains("<host starttime=\"1\" endtime=\"3\">"), out);
        assertTrue(out.contains("<hostnames><hostname name=\"web.lan\" type=\"PTR\"/></hostnames>"), out);
        assertTrue(out.contains("<host>\n    <status state=\"down\" reason=\"no-response\"/>"), "no times when unset: " + out);
        assertTrue(out.contains("<finished time=\"3\" timestr=\""), out);
        assertTrue(out.contains(" elapsed=\"2.50\" summary=\"NoSneak done at "), out);
        assertTrue(out.contains("; 2 IP addresses (1 host up) scanned in 2.50 seconds\"/>"), out);
        assertTrue(out.contains("<hosts up=\"1\" down=\"1\" total=\"2\"/>"), out);
        assertFalse(out.contains("<os>"), "OS detection is refused by policy; no dead element");
    }

    @Test
    public void xmlScaninfoListsTheRequestedPortsAsRangesPerProtocol() {
        ScanReport r = report(false);
        r.config = new NMapConfig().target("10.0.0.9")
                .ports(new int[]{8080, 1, 2, 3, 443}).udpPorts(new int[]{53, 123});
        String out = render(OutputFormat.XML, r);
        assertTrue(out.contains("<scaninfo type=\"connect\" protocol=\"tcp\" numservices=\"5\" services=\"1-3,443,8080\"/>"), out);
        assertTrue(out.contains("<scaninfo type=\"udp\" protocol=\"udp\" numservices=\"2\" services=\"53,123\"/>"), out);

        r.config = null; // a hand-built report: the union of what the hosts recorded
        String derived = render(OutputFormat.XML, r);
        assertTrue(derived.contains("numservices=\"5\" services=\"22,80,443,8080,9000\"/>"), derived);
    }

    @Test
    public void csvAppendsReasonAndRttColumnsAndWritesARowPerDownHost() {
        String out = render(OutputFormat.CSV, report(false));
        String[] lines = out.split("\n");
        assertTrue(lines[0].endsWith(",banner,reason,rttms"), lines[0]);
        assertTrue(out.contains("10.0.0.9,10.0.0.9,,b8:27:eb:30:40:d7,443,tcp,open,https,,,,,,connected,25"), out);
        assertTrue(out.contains(",80,tcp,closed,http,,,,,,conn-refused,\n"), out);
        assertTrue(out.endsWith("10.0.0.250,,,,,,,,,,,,,,\n"), "the down host is one row with every port column empty: " + out);
        assertEquals(7, lines.length, "header + five listed ports + the down host's row");
        assertEquals(15, lines[6].split(",", -1).length, "the down row has the header's column count");

        String open = render(OutputFormat.CSV, report(true));
        assertEquals(4, open.split("\n").length, "header + the two open ports + the down host");
    }

    @Test
    public void grepableCarriesReasonAndRttInTheOwnerAndRpcSlots() {
        String out = render(OutputFormat.GREPABLE, report(false));
        assertTrue(out.contains("443/open/tcp/connected/25ms//https//"), out);
        assertTrue(out.contains("80/closed/tcp/conn-refused///http//"), out);
        assertTrue(out.contains("Ignored State: 0 closed, 0 filtered"), out);
        assertTrue(out.contains("Host: 10.0.0.250 ()\tStatus: Down"), out);

        String open = render(OutputFormat.GREPABLE, report(true));
        assertFalse(open.contains("80/closed"), open);
        assertTrue(open.contains("Ignored State: 1 closed, 2 filtered"), open);
    }

    @Test
    public void grepableHasNmapHeaderFooterAndHostnameParens() {
        ScanReport r = report(false);
        r.hosts.getFirst().hostname = "web.lan";
        String out = render(OutputFormat.GREPABLE, r);
        String[] lines = out.split("\n");
        assertTrue(lines[0].startsWith("# Nmap-compatible scan initiated "), lines[0]);
        assertTrue(lines[0].endsWith(" as: xnmap -p 22,80,443,8080,9000 10.0.0.9"), lines[0]);
        assertTrue(lines[1].startsWith("Host: 10.0.0.9 (web.lan)\tStatus: Up\tPorts: "), lines[1]);
        assertTrue(lines[2].startsWith("Host: 10.0.0.250 ()\tStatus: Down"), lines[2]);
        assertTrue(lines[3].startsWith("# NoSneak done at "), lines[3]);
        assertTrue(lines[3].endsWith(" -- 2 IP addresses (1 host up) scanned in 2.50 seconds"), lines[3]);
        assertEquals(4, lines.length);
    }

    // ---- formatter API: mime types and streaming ----

    @Test
    public void everyFormatterNamesItsMimeTypeAndStreamsUtf8() throws Exception {
        assertEquals("text/plain", OutputFormat.formatter(OutputFormat.NORMAL).mimeType());
        assertEquals("application/xml", OutputFormat.formatter(OutputFormat.XML).mimeType());
        assertEquals("application/json", OutputFormat.formatter(OutputFormat.JSON).mimeType());
        assertEquals("text/csv", OutputFormat.formatter(OutputFormat.CSV).mimeType());
        assertEquals("text/plain", OutputFormat.formatter(OutputFormat.GREPABLE).mimeType());

        ScanReport r = report(false);
        r.hosts.getFirst().hostname = "café.lan"; // a non-ASCII byte proves the encoding
        for (OutputFormat f : OutputFormat.values()) {
            OutputFormatter fmt = OutputFormat.formatter(f);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            fmt.formatTo(r, bytes);
            assertArrayEquals(fmt.render(r).getBytes(StandardCharsets.UTF_8), bytes.toByteArray(), f.name());
            assertEquals(f.mimeType(), fmt.mimeType());
        }
    }
}
