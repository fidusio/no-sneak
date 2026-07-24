package io.xlogistx.nosneak.probe;

import io.xlogistx.nosneak.probe.model.PatternRule;
import io.xlogistx.nosneak.probe.model.ProbeDefinition;
import io.xlogistx.nosneak.probe.model.ProbeDefinitionLoader;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pure, no-network tests for the JSON probe model: bundled definitions load and
 * validate, the graph validator rejects malformed definitions, and pattern
 * rules match as expected.
 */
public class ProbeDefinitionLoaderTest {

    @Test
    public void bundledDefinitionsLoadAndValidate() {
        List<ProbeDefinition> defs = ProbeDefinitionLoader.loadBundled();
        assertEquals(ProbeDefinitionLoader.BUNDLED.length, defs.size());

        // Returned in descending priority order.
        for (int i = 1; i < defs.size(); i++) {
            assertTrue(defs.get(i - 1).getPriority() >= defs.get(i).getPriority(),
                    "definitions must be sorted by descending priority");
        }

        java.util.Set<String> names = new java.util.HashSet<>();
        for (ProbeDefinition def : defs) {
            assertNotNull(def.getStart());
            assertNotNull(def.state(def.getStart()), "start state must exist");
            // Re-running validation must not throw for a bundled (valid) probe.
            ProbeDefinitionLoader.validate(def, def.getName());
            names.add(def.getName());
        }
        assertTrue(names.containsAll(java.util.Arrays.asList(
                "https-pqc", "smtp-starttls-pqc", "mongodb", "imaps-pqc", "imap-starttls-pqc")));
    }

    @Test
    public void definitionsMatchExpectedPortsAndTransport() {
        ProbeDefinition https = ProbeDefinitionLoader.load("/probes/https-pqc.json");
        assertTrue(https.matches(443, "tcp"));
        assertTrue(https.matches(8443, "tcp"));
        assertFalse(https.matches(443, "udp"));
        assertFalse(https.matches(25, "tcp"));

        ProbeDefinition smtp = ProbeDefinitionLoader.load("/probes/smtp-starttls-pqc.json");
        assertTrue(smtp.matches(25, "tcp"));
        assertTrue(smtp.matches(587, "tcp"));
        assertFalse(smtp.matches(443, "tcp"));
    }

    @Test
    public void mongodbProbeCarriesBinarySendPayload() {
        ProbeDefinition mongo = ProbeDefinitionLoader.load("/probes/mongodb.json");
        assertTrue(mongo.matches(27017, "tcp"));
        assertFalse(mongo.matches(443, "tcp"));
        // The handshake is a binary (hex-encoded) wire message, not text.
        String data = mongo.state("hello").getData();
        assertNotNull(data, "send state must carry a binary data payload");
        assertTrue(data.startsWith("hex:"), "mongodb handshake should be hex-encoded binary");
        // Decodes to the 58-byte isMaster OP_QUERY message.
        byte[] bytes = org.zoxweb.shared.util.SharedStringUtil.hexToBytes(data.substring(4));
        assertEquals(58, bytes.length);
    }

    @Test
    public void validatorRejectsMissingStart() {
        String json = "{ \"name\":\"x\", \"start\":\"nope\", "
                + "\"states\": { \"done\": { \"action\":\"done\" } } }";
        ProbeDefinition def = GSONUtil.fromJSONDefault(json, ProbeDefinition.class);
        assertThrows(IllegalArgumentException.class, () -> ProbeDefinitionLoader.validate(def, "test"));
    }

    @Test
    public void validatorRejectsDanglingTransition() {
        String json = "{ \"name\":\"x\", \"start\":\"a\", \"states\": {"
                + " \"a\": { \"action\":\"connect\", \"on\": { \"connected\":\"ghost\" } },"
                + " \"done\": { \"action\":\"done\" } } }";
        ProbeDefinition def = GSONUtil.fromJSONDefault(json, ProbeDefinition.class);
        assertThrows(IllegalArgumentException.class, () -> ProbeDefinitionLoader.validate(def, "test"));
    }

    @Test
    public void validatorRejectsUnknownAction() {
        String json = "{ \"name\":\"x\", \"start\":\"a\", \"states\": {"
                + " \"a\": { \"action\":\"teleport\", \"on\": { \"done\":\"done\" } },"
                + " \"done\": { \"action\":\"done\" } } }";
        ProbeDefinition def = GSONUtil.fromJSONDefault(json, ProbeDefinition.class);
        assertThrows(IllegalArgumentException.class, () -> ProbeDefinitionLoader.validate(def, "test"));
    }

    @Test
    public void validatorRejectsNoReachableTerminal() {
        // 'a' -> 'b' -> 'a' cycle, no done/fail reachable.
        String json = "{ \"name\":\"x\", \"start\":\"a\", \"states\": {"
                + " \"a\": { \"action\":\"connect\", \"on\": { \"connected\":\"b\" } },"
                + " \"b\": { \"action\":\"connect\", \"on\": { \"connected\":\"a\" } } } }";
        ProbeDefinition def = GSONUtil.fromJSONDefault(json, ProbeDefinition.class);
        assertThrows(IllegalArgumentException.class, () -> ProbeDefinitionLoader.validate(def, "test"));
    }

    @Test
    public void patternRulesMatch() {
        assertTrue(new PatternRule("^220[ -]", "ok").pattern().matcher("220 mail.example.com ESMTP").find());
        assertTrue(new PatternRule("^220[ -]", "ok").pattern().matcher("220-first line").find());
        assertFalse(new PatternRule("^220[ -]", "ok").pattern().matcher("250 OK").find());
        assertTrue(new PatternRule("STARTTLS", "cap").pattern().matcher("250-STARTTLS\r\n250 HELP").find());
        assertFalse(new PatternRule("STARTTLS", "cap").pattern().matcher("250-PIPELINING\r\n250 HELP").find());
    }
}
