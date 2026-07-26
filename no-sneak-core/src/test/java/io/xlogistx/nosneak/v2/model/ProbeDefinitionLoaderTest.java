package io.xlogistx.nosneak.v2.model;

import io.xlogistx.nosneak.v2.action.ActionRegistry;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pure, no-network tests for the JSON probe model: every bundled definition loads and
 * validates, the graph validator rejects malformed definitions, the action library and the
 * validator's action list stay in sync, and pattern/capture rules deserialize correctly.
 */
public class ProbeDefinitionLoaderTest {

    @Test
    public void bundledDefinitionsLoadAndValidate() {
        List<ProbeDefinition> defs = ProbeDefinitionLoader.loadBundled();
        assertEquals(ProbeDefinitionLoader.BUNDLED.length, defs.size());

        for (int i = 1; i < defs.size(); i++) {
            assertTrue(defs.get(i - 1).getPriority() >= defs.get(i).getPriority(),
                    "definitions must be returned in descending priority order");
        }

        Set<String> names = new HashSet<>();
        for (ProbeDefinition def : defs) {
            assertNotNull(def.getStart(), def.getName() + " must declare a start state");
            assertNotNull(def.state(def.getStart()), def.getName() + " start state must exist");
            assertNotNull(def.getService(), def.getName() + " must declare a service");
            // Re-running validation must not throw for a bundled (valid) probe.
            ProbeDefinitionLoader.validate(def, def.getName());
            assertTrue(names.add(def.getName()), "duplicate probe name: " + def.getName());
        }

        // Every bundled resource must be represented — catches a resource added to BUNDLED
        // without a file, or a renamed probe.
        for (String path : ProbeDefinitionLoader.BUNDLED) {
            String file = path.substring(path.lastIndexOf('/') + 1).replace(".json", "");
            assertTrue(names.contains(file),
                    "bundled resource " + path + " did not yield a probe named '" + file + "'");
        }
    }

    /**
     * The validator's whitelist and the action library must not drift: a definition using an
     * action the validator accepts but the registry cannot build would fail at run time
     * (mid-scan) instead of at load time.
     */
    @Test
    public void everyKnownActionIsRegistered() {
        for (String action : ProbeDefinitionLoader.KNOWN_ACTIONS) {
            assertNotNull(ActionRegistry.get(action), "no Action registered for '" + action + "'");
            assertEquals(action, ActionRegistry.get(action).name());
        }
    }

    @Test
    public void everyBundledActionIsKnown() {
        for (ProbeDefinition def : ProbeDefinitionLoader.loadBundled()) {
            for (Map.Entry<String, ProbeState> e : def.getStates().entrySet()) {
                assertTrue(ProbeDefinitionLoader.KNOWN_ACTIONS.contains(e.getValue().getAction()),
                        def.getName() + "." + e.getKey() + " uses unknown action "
                                + e.getValue().getAction());
            }
        }
    }

    /**
     * Ungated any-TLS probes must be port-scoped so they cannot claim an unrelated TLS service
     * (the Postgres-over-TLS-reported-as-https bug); gated probes stay fallback-eligible.
     */
    @Test
    public void ungatedTlsCatchAllsArePortScoped() {
        assertTrue(ProbeDefinitionLoader.load("/v2/probes/https-pqc.json").isPortScoped());
        assertTrue(ProbeDefinitionLoader.load("/v2/probes/imaps-pqc.json").isPortScoped());
        assertTrue(ProbeDefinitionLoader.load("/v2/probes/https-scan.json").isPortScoped());
        assertFalse(ProbeDefinitionLoader.load("/v2/probes/https-version.json").isPortScoped());
        assertFalse(ProbeDefinitionLoader.load("/v2/probes/postgres-db.json").isPortScoped());
    }

    /**
     * {@code tls-scan} is the deep-analysis fallback for a nonstandard TLS port: it must declare
     * no ports (never tier-1), stay non-portScoped (always fallback-eligible), and outrank the
     * shallow probes.
     */
    @Test
    public void tlsScanIsTheDeepFallback() {
        ProbeDefinition tlsScan = ProbeDefinitionLoader.load("/v2/probes/tls-scan.json");
        assertFalse(tlsScan.isPortScoped());
        assertTrue(tlsScan.getPorts() == null || tlsScan.getPorts().length == 0,
                "tls-scan must declare no ports so it is never a tier-1 candidate");
        assertEquals("tls", tlsScan.getService());
        assertTrue(tlsScan.getPriority()
                        > ProbeDefinitionLoader.load("/v2/probes/https-version.json").getPriority(),
                "tls-scan must outrank the shallow https-version probe in the fallback tier");
    }

    /** https-scan must win on a declared TLS port: it outranks the shallower TLS probes. */
    @Test
    public void httpsScanOutranksShallowProbes() {
        int scan = ProbeDefinitionLoader.load("/v2/probes/https-scan.json").getPriority();
        assertTrue(scan > ProbeDefinitionLoader.load("/v2/probes/https-pqc.json").getPriority());
        assertTrue(scan > ProbeDefinitionLoader.load("/v2/probes/https-version.json").getPriority());
    }

    @Test
    public void matchesPortAndTransport() {
        ProbeDefinition ssh = ProbeDefinitionLoader.load("/v2/probes/ssh.json");
        assertTrue(ssh.matches(22, "tcp"));
        assertFalse(ssh.matches(22, "udp"));
        assertFalse(ssh.matches(443, "tcp"));

        ProbeDefinition dns = ProbeDefinitionLoader.load("/v2/probes/dns.json");
        assertEquals("udp", dns.getTransport());
        assertTrue(dns.matches(53, "udp"));
        assertFalse(dns.matches(53, "tcp"));
    }

    // ==================== Validator rejections ====================

    @Test
    public void rejectsDanglingTransition() {
        String json = "{ \"name\": \"bad\", \"service\": \"x\", \"ports\": [1], \"start\": \"a\","
                + " \"states\": { \"a\": { \"action\": \"connect\", \"on\": { \"connected\": \"nowhere\" } },"
                + " \"done\": { \"action\": \"done\" } } }";
        assertThrows(IllegalArgumentException.class, () -> validate(json));
    }

    @Test
    public void rejectsUnknownAction() {
        String json = "{ \"name\": \"bad\", \"service\": \"x\", \"ports\": [1], \"start\": \"a\","
                + " \"states\": { \"a\": { \"action\": \"launch-missiles\", \"on\": { \"x\": \"done\" } },"
                + " \"done\": { \"action\": \"done\" } } }";
        assertThrows(IllegalArgumentException.class, () -> validate(json));
    }

    @Test
    public void rejectsMissingStartState() {
        String json = "{ \"name\": \"bad\", \"service\": \"x\", \"ports\": [1], \"start\": \"ghost\","
                + " \"states\": { \"done\": { \"action\": \"done\" } } }";
        assertThrows(IllegalArgumentException.class, () -> validate(json));
    }

    @Test
    public void rejectsUnreachableTerminal() {
        // 'fail' exists but nothing routes to it, and the start state loops forever.
        String json = "{ \"name\": \"bad\", \"service\": \"x\", \"ports\": [1], \"start\": \"a\","
                + " \"states\": { \"a\": { \"action\": \"expect\", \"on\": { \"timeout\": \"a\" } },"
                + " \"fail\": { \"action\": \"fail\" } } }";
        assertThrows(IllegalArgumentException.class, () -> validate(json));
    }

    @Test
    public void rejectsNonTerminalStateWithoutTransitions() {
        String json = "{ \"name\": \"bad\", \"service\": \"x\", \"ports\": [1], \"start\": \"a\","
                + " \"states\": { \"a\": { \"action\": \"connect\" }, \"done\": { \"action\": \"done\" } } }";
        assertThrows(IllegalArgumentException.class, () -> validate(json));
    }

    @Test
    public void rejectsMissingResource() {
        assertThrows(IllegalArgumentException.class,
                () -> ProbeDefinitionLoader.load("/v2/probes/does-not-exist.json"));
    }

    // ==================== Pattern / capture model ====================

    @Test
    public void patternRuleCompilesAndCaptures() {
        String json = "{ \"regex\": \"^SSH-\\\\d+\\\\.\\\\d+-([^\\\\r\\\\n]*)\","
                + " \"outcome\": \"ssh\", \"capture\": \"version\" }";
        PatternRule rule = GSONUtil.fromJSONDefault(json, PatternRule.class);
        assertEquals("ssh", rule.getOutcome());
        assertEquals("version", rule.getCapture());
        assertEquals(1, rule.getCaptureGroup(), "capture group must default to 1");

        java.util.regex.Matcher m = rule.pattern().matcher("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n");
        assertTrue(m.find());
        assertEquals("OpenSSH_9.6p1 Ubuntu-3", m.group(rule.getCaptureGroup()));
        // The compiled pattern is cached, not rebuilt per match.
        assertTrue(rule.pattern() == rule.pattern());
    }

    @Test
    public void patternRuleWithoutCaptureExtractsNothing() {
        PatternRule rule = GSONUtil.fromJSONDefault(
                "{ \"regex\": \"\\\\+PONG\", \"outcome\": \"ok\" }", PatternRule.class);
        assertEquals(null, rule.getCapture());
        assertTrue(rule.pattern().matcher("+PONG\r\n").find());
    }

    /** ISO-8859-1 keeps bytes 0-255 intact, so ASCII markers match inside binary replies. */
    @Test
    public void patternMatchesAsciiMarkerInsideBinaryPayload() {
        PatternRule rule = GSONUtil.fromJSONDefault(
                "{ \"regex\": \"ismaster|maxWireVersion\", \"outcome\": \"mongo\" }", PatternRule.class);
        byte[] binary = new byte[]{0x3a, 0x00, (byte) 0xd4, 0x07, 'i', 's', 'm', 'a', 's', 't', 'e', 'r', 0x00};
        String decoded = new String(binary, java.nio.charset.StandardCharsets.ISO_8859_1);
        assertTrue(rule.pattern().matcher(decoded).find());
    }

    private static void validate(String json) {
        ProbeDefinition def = GSONUtil.fromJSONDefault(json, ProbeDefinition.class);
        ProbeDefinitionLoader.validate(def, "inline-test");
    }
}
