package io.xlogistx.nosneak.runtime;

import io.xlogistx.nosneak.analysis.CipherProbeCallback;
import io.xlogistx.nosneak.analysis.GroupProbeCallback;
import io.xlogistx.nosneak.analysis.ProbeCallbackSeams;
import io.xlogistx.nosneak.analysis.VersionProbeCallback;
import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.result.ProbeResult;
import io.xlogistx.nosneak.tls.PQCTlsClient;
import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.tls.NamedGroup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.shared.net.IPAddress;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static io.xlogistx.nosneak.runtime.ScriptedTransport.connected;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The three enumeration actions driven through {@link ProbeContext} with no socket: the
 * {@link ScriptedTransport} records every child the context opens, and the test plays the peer
 * for each one through {@link ProbeCallbackSeams}. Pins the candidate sets the toggles produce,
 * the bounded launcher's window, the best-first recording, the preference probe, and the
 * server-ranking chain.
 */
public class TlsEnumerationContextTest {

    private static final IPAddress TARGET = new IPAddress("127.0.0.1", 443);
    private static final int TIMEOUT = 3;

    private ScriptedTransport tx;
    private ManualScheduler clock;

    @BeforeEach
    public void fresh() {
        tx = new ScriptedTransport();
        clock = new ManualScheduler();
    }

    /** connect → one enumeration state (with {@code extra} JSON fields) → done. */
    private static ProbeDefinition oneStep(String action, String extra) {
        String json = "{\"name\":\"enum\",\"service\":\"tls\",\"ports\":[443],\"start\":\"connect\",\"states\":{"
                + "\"connect\":{\"action\":\"connect\",\"on\":{\"connected\":\"step\",\"error\":\"fail\",\"timeout\":\"fail\"}},"
                + "\"step\":{\"action\":\"" + action + "\"" + extra + ",\"on\":{\"done\":\"done\"}},"
                + "\"done\":{\"action\":\"done\"},\"fail\":{\"action\":\"fail\"}}}";
        return ProbeDefinitionLoader.parse(json, "enum");
    }

    private ProbeContext enter(ProbeDefinition def) {
        ProbeContext ctx = tx.newContext(clock, TARGET, def, TIMEOUT);
        ctx.start();
        connected(tx.last());
        assertEquals("step", ctx.currentStateId());
        return ctx;
    }

    private ProbeResult delivered() {
        assertEquals(1, tx.delivered.size(), "exactly one result");
        return tx.delivered.get(0);
    }

    // ==================== enumerate-versions ====================

    private List<String> versionNames() {
        List<String> out = new ArrayList<>();
        for (TCPSessionCallback cb : tx.analysisOpens) {
            out.add(((VersionProbeCallback) cb).versionName());
        }
        return out;
    }

    private VersionProbeCallback version(String name) {
        for (TCPSessionCallback cb : tx.analysisOpens) {
            VersionProbeCallback v = (VersionProbeCallback) cb;
            if (name.equals(v.versionName())) {
                return v;
            }
        }
        throw new IllegalStateException("no child for " + name);
    }

    @Test
    public void allFiveVersionsAreOfferedByDefaultAndRecordedBestFirst() {
        enter(oneStep("enumerate-versions", ""));
        assertEquals(List.of("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"), versionNames());
        assertTrue(tx.delivered.isEmpty(), "the join waits for every child");

        // Complete out of order: the recorded list must still read best-first.
        ProbeCallbackSeams.accept(version("TLSv1.0"));
        ProbeCallbackSeams.reject(version("SSLv3"));
        ProbeCallbackSeams.accept(version("TLSv1.2"));
        ProbeCallbackSeams.reject(version("TLSv1.1"));
        assertTrue(tx.delivered.isEmpty(), "one child still outstanding");
        ProbeCallbackSeams.accept(version("TLSv1.3"));

        ProbeResult r = delivered();
        assertEquals(List.of("TLSv1.3", "TLSv1.2", "TLSv1.0"), r.getSupportedProtocolVersions());
        assertTrue(r.isSuccess());
        assertNull(r.getErrorMessage());
        assertEquals(0, clock.liveCount(), "no timer survives delivery");
    }

    @Test
    public void includeSslv3FalseOpensFourVersionChildrenInsteadOfFive() {
        enter(oneStep("enumerate-versions", ",\"includeSSLv3\":false"));
        assertEquals(4, tx.analysisOpens.size());
        assertEquals(List.of("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"), versionNames());
    }

    @Test
    public void everyLegacyToggleOffLeavesOnlyTheModernPair() {
        enter(oneStep("enumerate-versions", ",\"includeSSLv3\":false,\"includeTLS10\":false,\"includeTLS11\":false"));
        assertEquals(List.of("TLSv1.3", "TLSv1.2"), versionNames());
        ProbeCallbackSeams.reject(version("TLSv1.2"));
        ProbeCallbackSeams.reject(version("TLSv1.3"));
        assertTrue(delivered().getSupportedProtocolVersions().isEmpty(), "nothing accepted, nothing recorded");
    }

    // ==================== enumerate-ciphers ====================

    /** The suites the scripted server accepts: two TLS 1.3, two strong and one weak TLS 1.2. */
    private static Set<Integer> acceptedSuites() {
        Set<Integer> accept = new HashSet<>();
        accept.add(OPSecUtil.ALL_TLS13_CIPHERS[0]);
        accept.add(OPSecUtil.ALL_TLS13_CIPHERS[1]);
        accept.add(OPSecUtil.ALL_TLS12_STRONG[0]);
        accept.add(OPSecUtil.ALL_TLS12_STRONG[1]);
        accept.add(OPSecUtil.ALL_TLS12_WEAK[0]);
        return accept;
    }

    /** The suite a server that enforces its own order prefers — deliberately not our first. */
    private static final int SERVER_FAVOURITE = OPSecUtil.ALL_TLS12_STRONG[1];

    private static boolean offers(int[] offer, int suite) {
        for (int c : offer) {
            if (c == suite) return true;
        }
        return false;
    }

    /**
     * Plays the peer for every cipher child the context opens, in the order they were opened:
     * a single-suite offer is accepted when the suite is in {@code accept}; a multi-suite offer
     * (the preference probes, then the ranking steps) is answered with {@code favourite} when it
     * is offered, otherwise with the first suite of the offer (what a client-ordered server
     * does). Children opened by a completion are reached by the same loop.
     *
     * @return the largest number of children open-but-unanswered at any moment
     */
    private int playCiphers(Set<Integer> accept, Integer favourite) {
        int served = 0;
        int peak = 0;
        int i = 0;
        while (i < tx.analysisOpens.size()) {
            peak = Math.max(peak, tx.analysisOpens.size() - served);
            CipherProbeCallback p = (CipherProbeCallback) tx.analysisOpens.get(i++);
            int[] offer = p.offered();
            if (offer.length == 1) {
                if (accept.contains(offer[0])) {
                    ProbeCallbackSeams.accept(p, offer[0]);
                } else {
                    ProbeCallbackSeams.reject(p);
                }
            } else {
                int pick = favourite != null && offers(offer, favourite) ? favourite : offer[0];
                ProbeCallbackSeams.accept(p, pick);
            }
            served++;
        }
        return peak;
    }

    private int singleSuiteOpens() {
        int n = 0;
        for (TCPSessionCallback cb : tx.analysisOpens) {
            if (((CipherProbeCallback) cb).offered().length == 1) n++;
        }
        return n;
    }

    private int multiSuiteOpens() {
        return tx.analysisOpens.size() - singleSuiteOpens();
    }

    @Test
    public void theDefaultSweepOffersEverySuiteEightAtATimeAndRecordsComponents() {
        enter(oneStep("enumerate-ciphers", ""));
        assertEquals(ProbeContext.DEFAULT_MAX_IN_FLIGHT, tx.analysisOpens.size(),
                "only the first window is open until a child completes");

        int peak = playCiphers(acceptedSuites(), SERVER_FAVOURITE);

        assertEquals(ProbeContext.DEFAULT_MAX_IN_FLIGHT, peak, "the launcher never exceeds its window");
        int all = OPSecUtil.ALL_TLS13_CIPHERS.length + OPSecUtil.ALL_TLS12_STRONG.length
                + OPSecUtil.ALL_TLS12_WEAK.length + OPSecUtil.ALL_TLS12_INSECURE.length;
        assertEquals(all, singleSuiteOpens(), "every candidate suite was offered once");
        assertEquals(2, multiSuiteOpens(), "the forward and reversed preference probes, nothing more");

        ProbeResult r = delivered();
        assertEquals(5, r.getSupportedCipherSuites().size());
        assertEquals(5, r.getSupportedCipherSuiteDetails().size());
        for (ProbeResult.CipherSuiteInfo s : r.getSupportedCipherSuiteDetails()) {
            assertNotNull(s.keyExchange, s.name);
            assertNotNull(s.authentication, s.name);
            assertNotNull(s.encryption, s.name);
            assertNotNull(s.mac, s.name);
            assertNotNull(s.strength, s.name);
        }
        // TLS 1.3 suites are recorded first and at their version; TLS 1.2 after.
        assertEquals("TLSv1.3", r.getSupportedCipherSuiteDetails().get(0).version);
        assertEquals("TLSv1.2", r.getSupportedCipherSuiteDetails().get(4).version);
        assertEquals(PQCTlsClient.getCipherSuiteName(SERVER_FAVOURITE), r.getServerCipherPreference());
        assertEquals("server", r.getServerCipherPreferenceMode(),
                "the same pick in both orders means the server decides");
        assertTrue(r.getServerCipherRanking().isEmpty(), "ranking is opt-in");
        assertTrue(r.isSuccess());
    }

    @Test
    public void weakAndInsecureTogglesShrinkTheOffer() {
        enter(oneStep("enumerate-ciphers", ",\"includeWeak\":false,\"includeInsecure\":false"));
        playCiphers(acceptedSuites(), SERVER_FAVOURITE);
        assertEquals(OPSecUtil.ALL_TLS13_CIPHERS.length + OPSecUtil.ALL_TLS12_STRONG.length, singleSuiteOpens(),
                "only the TLS 1.3 and strong TLS 1.2 sets are offered");
        ProbeResult r = delivered();
        assertEquals(4, r.getSupportedCipherSuites().size(), "the weak suite was never offered, so never seen");
    }

    @Test
    public void maxInFlightCapsTheWindow() {
        enter(oneStep("enumerate-ciphers", ",\"maxInFlight\":3"));
        assertEquals(3, tx.analysisOpens.size());
        int peak = playCiphers(acceptedSuites(), SERVER_FAVOURITE);
        assertEquals(3, peak);
        assertEquals(5, delivered().getSupportedCipherSuites().size(), "the window changes pacing, not coverage");
    }

    @Test
    public void rankServerPreferenceDerivesTheServersOrderOneHandshakeAtATime() {
        enter(oneStep("enumerate-ciphers", ",\"rankServerPreference\":true"));
        playCiphers(acceptedSuites(), SERVER_FAVOURITE);

        ProbeResult r = delivered();
        assertEquals("server", r.getServerCipherPreferenceMode());
        List<String> ranking = r.getServerCipherRanking();
        assertEquals(3, ranking.size(), "every accepted TLS 1.2 suite is ranked: " + ranking);
        assertEquals(PQCTlsClient.getCipherSuiteName(SERVER_FAVOURITE), ranking.get(0), "the preference pick leads");
        assertEquals(PQCTlsClient.getCipherSuiteName(OPSecUtil.ALL_TLS12_STRONG[0]), ranking.get(1));
        assertEquals(PQCTlsClient.getCipherSuiteName(OPSecUtil.ALL_TLS12_WEAK[0]), ranking.get(2));
        // 44 single-suite children, two preference probes, then one handshake per remaining suite
        // (the last of which offers a single suite): sequential, never a burst.
        int all = OPSecUtil.ALL_TLS13_CIPHERS.length + OPSecUtil.ALL_TLS12_STRONG.length
                + OPSecUtil.ALL_TLS12_WEAK.length + OPSecUtil.ALL_TLS12_INSECURE.length;
        assertEquals(all + 2 + 2, tx.analysisOpens.size());
        assertTrue(r.isSuccess());
    }

    @Test
    public void aClientOrderedServerIsNotRankedEvenWhenAsked() {
        enter(oneStep("enumerate-ciphers", ",\"rankServerPreference\":true"));
        playCiphers(acceptedSuites(), null); // the pick follows our order: forward != reversed

        ProbeResult r = delivered();
        assertEquals("client", r.getServerCipherPreferenceMode());
        assertTrue(r.getServerCipherRanking().isEmpty(), "no server order to derive");
        assertEquals(2, multiSuiteOpens(), "the preference probes only");
    }

    @Test
    public void aSingleAcceptedSuiteNeedsNoPreferenceProbe() {
        enter(oneStep("enumerate-ciphers", ""));
        Set<Integer> only = new HashSet<>();
        only.add(OPSecUtil.ALL_TLS12_STRONG[0]);
        playCiphers(only, null);

        ProbeResult r = delivered();
        assertEquals(0, multiSuiteOpens());
        assertEquals("only-one-accepted", r.getServerCipherPreferenceMode());
        assertEquals(PQCTlsClient.getCipherSuiteName(OPSecUtil.ALL_TLS12_STRONG[0]), r.getServerCipherPreference());
    }

    @Test
    public void aServerThatAcceptsNothingStillCompletes() {
        enter(oneStep("enumerate-ciphers", ""));
        playCiphers(new HashSet<>(), null);
        ProbeResult r = delivered();
        assertTrue(r.getSupportedCipherSuites().isEmpty());
        assertNull(r.getServerCipherPreferenceMode());
        assertTrue(r.isSuccess(), "an empty observation is still a completed probe");
    }

    // ==================== enumerate-groups ====================

    @Test
    public void groupsAreOfferedSinglyWithinTheWindowAndRecordedHybridsFirst() {
        enter(oneStep("enumerate-groups", ""));
        assertEquals(ProbeContext.DEFAULT_MAX_IN_FLIGHT, tx.analysisOpens.size(),
                "ten candidates, eight in the first window");

        Set<Integer> accept = new HashSet<>();
        accept.add(NamedGroup.secp256r1);
        accept.add(NamedGroup.x25519);
        accept.add(NamedGroup.X25519MLKEM768);
        int served = 0;
        int peak = 0;
        int i = 0;
        while (i < tx.analysisOpens.size()) {
            peak = Math.max(peak, tx.analysisOpens.size() - served);
            GroupProbeCallback p = (GroupProbeCallback) tx.analysisOpens.get(i++);
            if (accept.contains(p.namedGroup())) {
                ProbeCallbackSeams.accept(p);
            } else {
                ProbeCallbackSeams.reject(p);
            }
            served++;
        }

        assertEquals(ProbeContext.DEFAULT_MAX_IN_FLIGHT, peak);
        assertEquals(GroupProbeCallback.CANDIDATE_GROUPS.length, tx.analysisOpens.size());
        ProbeResult r = delivered();
        assertEquals(List.of(GroupProbeCallback.groupName(NamedGroup.X25519MLKEM768),
                        GroupProbeCallback.groupName(NamedGroup.x25519),
                        GroupProbeCallback.groupName(NamedGroup.secp256r1)),
                r.getSupportedGroups(), "candidate order, hybrids first, whatever order the peer answered in");
        assertNull(r.getServerGroupPreference(), "no main handshake ran, so no preference to report");
        assertFalse(r.getSupportedGroups().isEmpty());
    }
}
