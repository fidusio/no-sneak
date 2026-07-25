package io.xlogistx.nosneak.probe;

import io.xlogistx.nosneak.probe.model.PatternRule;
import io.xlogistx.nosneak.probe.model.ProbeDefinition;
import io.xlogistx.nosneak.probe.model.ProbeDefinitionLoader;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;

import java.nio.charset.StandardCharsets;
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
                "https-pqc", "smtp-starttls-pqc", "mongodb", "imaps-pqc", "imap-starttls-pqc", "ssh",
                "ftp", "pop3", "redis", "mysql", "http", "postgres-db", "postgres-version",
                "postgres-tls", "https-version")));
    }

    @Test
    public void ungatedTlsCatchAllsArePortScoped() {
        // Ungated any-TLS probes must be port-scoped so they can't mislabel an unrelated TLS port.
        assertTrue(ProbeDefinitionLoader.load("/probes/https-pqc.json").isPortScoped());
        assertTrue(ProbeDefinitionLoader.load("/probes/imaps-pqc.json").isPortScoped());
        // Gated probes stay fallback-eligible (not port-scoped).
        assertFalse(ProbeDefinitionLoader.load("/probes/https-version.json").isPortScoped());
        assertFalse(ProbeDefinitionLoader.load("/probes/postgres-db.json").isPortScoped());
        assertFalse(ProbeDefinitionLoader.load("/probes/ssh.json").isPortScoped());
    }

    @Test
    public void secureHttpsProbeUsesTlsConnectAndCaptures() {
        // Loads only if "tls-connect" is a KNOWN_ACTIONS entry (else validate() throws).
        ProbeDefinition https = ProbeDefinitionLoader.load("/probes/https-version.json");
        assertTrue(https.matches(443, "tcp"));
        assertEquals("tls-connect", https.state(https.getStart()).getAction(),
                "the HTTPS version probe must open a secure channel via tls-connect");

        // The response state captures the Server header as the version fact.
        PatternRule serverRule = https.state("resp").getPatterns().get(0);
        assertEquals("version", serverRule.getCapture());
        java.util.regex.Matcher m = serverRule.pattern()
                .matcher("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n");
        assertTrue(m.find(), "Server header must match");
        assertEquals("nginx/1.24.0", m.group(serverRule.getCaptureGroup()).trim());
    }

    @Test
    public void plaintextVersionProbesCaptureAsExpected() {
        // FTP banner -> version
        PatternRule ftp = ProbeDefinitionLoader.load("/probes/ftp.json").state("banner").getPatterns().get(0);
        assertEquals("version", ftp.getCapture());
        java.util.regex.Matcher fm = ftp.pattern().matcher("220 (vsFTPd 3.0.3)\r\n");
        assertTrue(fm.find());
        assertEquals("(vsFTPd 3.0.3)", fm.group(1).trim());

        // Redis INFO -> redis_version
        PatternRule redis = ProbeDefinitionLoader.load("/probes/redis.json").state("reply").getPatterns().get(0);
        assertEquals("version", redis.getCapture());
        assertTrue(redis.pattern().matcher("$123\r\n# Server\r\nredis_version:7.2.4\r\n").find());

        // MySQL handshake (binary, ISO-8859-1): protocol-10 byte (0x0a) then a NUL-terminated
        // version C-string. Built as raw bytes to match the wire form unambiguously.
        PatternRule mysql = ProbeDefinitionLoader.load("/probes/mysql.json").state("handshake").getPatterns().get(0);
        String mysqlPkt = new String(
                new byte[]{0x0a, '8', '.', '0', '.', '3', '6', 0x00, 'r', 'e', 's', 't'},
                StandardCharsets.ISO_8859_1);
        java.util.regex.Matcher mm = mysql.pattern().matcher(mysqlPkt);
        assertTrue(mm.find());
        assertEquals("8.0.36", mm.group(1));

        // PostgreSQL StartupMessage is a valid even-length hex payload.
        ProbeDefinition pg = ProbeDefinitionLoader.load("/probes/postgres-version.json");
        String data = pg.state("startup").getData();
        assertTrue(data.startsWith("hex:"));
        assertEquals(0, (data.length() - 4) % 2, "hex payload must be even length");
        byte[] startup = org.zoxweb.shared.util.SharedStringUtil.hexToBytes(data.substring(4));
        assertEquals(startup.length, ((startup[0] & 0xff) << 24) | ((startup[1] & 0xff) << 16)
                | ((startup[2] & 0xff) << 8) | (startup[3] & 0xff), "length prefix must equal message length");
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

        // The buildInfo step is a well-formed OP_MSG (opcode 2013, self-consistent length) and its
        // expect rule captures the BSON `version` string.
        String bi = mongo.state("buildinfo").getData();
        assertTrue(bi.startsWith("hex:"));
        byte[] msg = org.zoxweb.shared.util.SharedStringUtil.hexToBytes(bi.substring(4));
        int msgLen = (msg[0] & 0xff) | ((msg[1] & 0xff) << 8) | ((msg[2] & 0xff) << 16) | ((msg[3] & 0xff) << 24);
        int opCode = (msg[12] & 0xff) | ((msg[13] & 0xff) << 8) | ((msg[14] & 0xff) << 16) | ((msg[15] & 0xff) << 24);
        assertEquals(msg.length, msgLen, "OP_MSG length prefix must equal message length");
        assertEquals(2013, opCode, "buildInfo must be sent as OP_MSG (opcode 2013)");

        PatternRule ver = mongo.state("buildResp").getPatterns().get(0);
        assertEquals("version", ver.getCapture());
        // Synthetic buildInfo BSON: \x02 version \0 <len=6> "7.0.5" \0, plus a versionArray decoy.
        String reply = new String(new byte[]{
                0x02, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x00, 0x06, 0x00, 0x00, 0x00,
                '7', '.', '0', '.', '5', 0x00, 0x04, 'v', 'e', 'r', 's', 'i', 'o', 'n', 'A', 'r', 'r', 'a', 'y', 0x00},
                StandardCharsets.ISO_8859_1);
        java.util.regex.Matcher vm = ver.pattern().matcher(reply);
        assertTrue(vm.find());
        assertEquals("7.0.5", vm.group(1));
    }

    @Test
    public void sshProbeCapturesVersionFromBanner() {
        ProbeDefinition ssh = ProbeDefinitionLoader.load("/probes/ssh.json");
        assertTrue(ssh.matches(22, "tcp"));
        assertTrue(ssh.matches(2222, "tcp"));
        assertFalse(ssh.matches(443, "tcp"));

        PatternRule rule = ssh.state("banner").getPatterns().get(0);
        assertEquals("version", rule.getCapture(), "banner rule must capture the 'version' fact");
        assertEquals(1, rule.getCaptureGroup(), "default capture group is 1");

        // The declared regex extracts the software string from a real SSH server-id line.
        java.util.regex.Matcher m = rule.pattern()
                .matcher("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n");
        assertTrue(m.find(), "SSH banner must match");
        assertEquals("OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", m.group(rule.getCaptureGroup()).trim());
    }

    @Test
    public void patternRuleWithoutCaptureExtractsNothing() {
        // A plain rule (no capture) leaves getCapture() null and defaults group to 1.
        PatternRule plain = new PatternRule("^220[ -]", "ok");
        assertEquals(null, plain.getCapture());
        assertEquals(1, plain.getCaptureGroup());

        // A capture rule deserialized from JSON exposes the configured name/group.
        PatternRule captured = GSONUtil.fromJSONDefault(
                "{ \"regex\":\"v=(\\\\d+)\", \"outcome\":\"ok\", \"capture\":\"version\", \"group\":1 }",
                PatternRule.class);
        assertEquals("version", captured.getCapture());
        java.util.regex.Matcher m = captured.pattern().matcher("proto v=42 ready");
        assertTrue(m.find());
        assertEquals("42", m.group(captured.getCaptureGroup()));
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
