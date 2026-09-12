package io.xlogistx.nosneak.v2.nmap;

import io.xlogistx.nosneak.v2.nmap.ScanReport.HostReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.PortReport;
import io.xlogistx.nosneak.v2.nmap.ScanReport.RenderSelection;
import io.xlogistx.nosneak.v2.nmap.output.OutputFormat;
import io.xlogistx.nosneak.v2.nmap.output.OutputFormatter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The five renderers are pure functions of a {@link ScanReport}; this builds one by hand and
 * pins what wave 1 populated and wave 2 renders: the per-port {@code reason}, the round-trip
 * time when measured, and the one shared rule behind {@code --open}.
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

    /**
     * JSON is the house serialiser over {@link ScanReport#toNVGenericMap()}, so the assertions
     * parse it back rather than string-match a layout: the shape is the contract, not the
     * whitespace.
     */
    @Test
    public void jsonCarriesReasonAndOnlyMeasuredRtt() {
        String out = render(OutputFormat.JSON, report(false));
        org.zoxweb.shared.util.NVGenericMap root =
                org.zoxweb.server.util.GSONUtil.fromJSONGenericMap(out.getBytes(java.nio.charset.StandardCharsets.UTF_8));
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
                org.zoxweb.server.util.GSONUtil.fromJSONGenericMap(out.getBytes(java.nio.charset.StandardCharsets.UTF_8));
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
    public void csvAppendsReasonAndRttColumns() {
        String out = render(OutputFormat.CSV, report(false));
        String[] lines = out.split("\n");
        assertTrue(lines[0].endsWith(",banner,reason,rttms"), lines[0]);
        assertTrue(out.contains("10.0.0.9,10.0.0.9,,b8:27:eb:30:40:d7,443,tcp,open,https,,,,,,connected,25"), out);
        assertTrue(out.contains(",80,tcp,closed,http,,,,,,conn-refused,\n"), out);
        assertEquals(6, lines.length, "header + five listed ports; the down host has no rows");

        String open = render(OutputFormat.CSV, report(true));
        assertEquals(3, open.split("\n").length, "header + the two open ports");
    }

    @Test
    public void grepableCarriesReasonAndRttInTheOwnerAndRpcSlots() {
        String out = render(OutputFormat.GREPABLE, report(false));
        assertTrue(out.contains("443/open/tcp/connected/25ms//https//"), out);
        assertTrue(out.contains("80/closed/tcp/conn-refused///http//"), out);
        assertTrue(out.contains("Ignored State: 0 closed, 0 filtered"), out);
        assertTrue(out.contains("Host: 10.0.0.250\tStatus: Down"), out);

        String open = render(OutputFormat.GREPABLE, report(true));
        assertFalse(open.contains("80/closed"), open);
        assertTrue(open.contains("Ignored State: 1 closed, 2 filtered"), open);
    }
}
