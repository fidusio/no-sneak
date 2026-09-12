package io.xlogistx.nosneak.v2;

import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.v2.result.ProbeResult;
import io.xlogistx.nosneak.v2.runtime.ManualScheduler;
import io.xlogistx.nosneak.v2.runtime.ScriptedTransport;
import io.xlogistx.nosneak.v2.runtime.ScriptedTransport.Conn;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.task.CallableConsumerTask;

import java.util.ArrayList;
import java.util.List;

import static io.xlogistx.nosneak.v2.runtime.ScriptedTransport.connected;
import static io.xlogistx.nosneak.v2.runtime.ScriptedTransport.inbound;
import static io.xlogistx.nosneak.v2.runtime.ScriptedTransport.peerClosed;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The candidate election, driven with no sockets (PENDING-ISSUES P12). Every candidate is a
 * banner probe that completes on {@code OK}; the test decides which "servers" answer, in which
 * order, and asserts who wins and who is cancelled.
 */
public class ProbeCheckerTest {

    private ScriptedTransport tx;
    private ManualScheduler clock;
    private final List<ProbeResult> delivered = new ArrayList<>();
    private final List<List<ProbeResult>> deliveredAll = new ArrayList<>();

    @BeforeEach
    public void fresh() {
        tx = new ScriptedTransport();
        clock = new ManualScheduler();
        delivered.clear();
        deliveredAll.clear();
    }

    /** A banner probe: connect, expect "OK", done. */
    static ProbeDefinition banner(String name, String service, int[] ports, int priority,
                                  boolean portScoped, String transport) {
        StringBuilder p = new StringBuilder("[");
        for (int i = 0; i < ports.length; i++) {
            p.append(i > 0 ? "," : "").append(ports[i]);
        }
        p.append("]");
        String json = "{\"name\":\"" + name + "\",\"service\":\"" + service + "\",\"transport\":\"" + transport
                + "\",\"ports\":" + p + ",\"priority\":" + priority + ",\"portScoped\":" + portScoped
                + ",\"start\":\"connect\",\"states\":{"
                + "\"connect\":{\"action\":\"connect\",\"on\":{\"connected\":\"banner\",\"error\":\"fail\",\"timeout\":\"fail\"}},"
                + "\"banner\":{\"action\":\"expect\",\"patterns\":[{\"regex\":\"^OK (\\\\S+)\",\"outcome\":\"ok\",\"capture\":\"version\"}],"
                + "\"on\":{\"ok\":\"done\",\"nomatch\":\"fail\",\"timeout\":\"fail\",\"error\":\"fail\"}},"
                + "\"done\":{\"action\":\"done\"},\"fail\":{\"action\":\"fail\"}}}";
        return ProbeDefinitionLoader.parse(json, name);
    }

    static ProbeDefinition banner(String name, int[] ports, int priority) {
        return banner(name, name + "-svc", ports, priority, false, "tcp");
    }

    private ProbeChecker checker(ProbeDefinition... defs) {
        List<ProbeDefinition> sorted = new ArrayList<>(List.of(defs));
        sorted.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));
        return new ProbeChecker(sorted, Runnable::run,
                (target, def, to, cb) -> tx.newContext(clock, target, def, to, cb)).timeoutInSec(3);
    }

    private void check(ProbeChecker c, int port) {
        c.check("127.0.0.1", port, new CallableConsumerTask<ProbeResult>().setConsumer(delivered::add));
    }

    private static void answer(Conn c, String version) {
        connected(c);
        inbound(c, "OK " + version + "\r\n");
    }

    private static void silence(Conn c) {
        connected(c);
        peerClosed(c);
    }

    // ---------------------------------------------------------------- ordering

    @Test
    public void declaredPortTierOutranksTheFallbackTierWhateverThePriorities() {
        ProbeDefinition declared = banner("low-but-declared", new int[]{22}, 10);
        ProbeDefinition fallback = banner("high-fallback", new int[]{80}, 90);
        List<ProbeDefinition> order = checker(declared, fallback).orderedCandidates(22, "tcp");
        assertEquals(List.of("low-but-declared", "high-fallback"), names(order));
    }

    @Test
    public void portScopedProbesNeverEnterTheFallbackTier() {
        ProbeDefinition scoped = banner("scoped", "https", new int[]{443}, 72, true, "tcp");
        ProbeDefinition open = banner("open", "tls", new int[]{}, 71, false, "tcp");
        assertEquals(List.of("open"), names(checker(scoped, open).orderedCandidates(8443, "tcp")));
        assertEquals(List.of("scoped", "open"), names(checker(scoped, open).orderedCandidates(443, "tcp")));
    }

    @Test
    public void priorityOrderIsPreservedWithinATier() {
        ProbeDefinition a = banner("a", new int[]{22}, 65);
        ProbeDefinition b = banner("b", new int[]{22}, 60);
        ProbeDefinition c = banner("c", new int[]{22}, 70);
        assertEquals(List.of("c", "a", "b"), names(checker(a, b, c).orderedCandidates(22, "tcp")));
    }

    @Test
    public void transportMismatchExcludesAProbeEntirely() {
        ProbeDefinition dns = banner("dns", "dns", new int[]{53}, 60, false, "udp");
        ProbeDefinition ssh = banner("ssh", new int[]{22}, 65);
        assertEquals(List.of("ssh"), names(checker(dns, ssh).orderedCandidates(53, "tcp")));
        assertEquals(List.of("dns"), names(checker(dns, ssh).orderedCandidates(53, "udp")));
    }

    @Test
    public void matchPortsOffFlattensEverythingIntoOnePriorityOrderedTier() {
        ProbeDefinition scoped = banner("scoped", "https", new int[]{443}, 72, true, "tcp");
        ProbeDefinition other = banner("other", new int[]{80}, 65);
        List<String> order = names(checker(scoped, other).matchPorts(false).orderedCandidates(9999, "tcp"));
        assertEquals(List.of("scoped", "other"), order);
    }

    // ---------------------------------------------------------------- the election

    @Test
    public void everyCandidateIsLaunchedAtOnce() {
        check(checker(banner("a", new int[]{22}, 70), banner("b", new int[]{22}, 60), banner("c", new int[]{}, 50)), 22);
        assertEquals(3, tx.connections.size());
        assertEquals(List.of("a", "b", "c"), List.of(tx.connections.get(0).probeName(),
                tx.connections.get(1).probeName(), tx.connections.get(2).probeName()));
    }

    @Test
    public void aLowerPriorityCompletionWaitsForTheHigherPriorityCandidate() {
        check(checker(banner("a", new int[]{22}, 70), banner("b", new int[]{22}, 60)), 22);

        answer(tx.connFor("b"), "b-1.0");
        assertEquals(0, delivered.size(), "b must wait: a could still win");

        silence(tx.connFor("a"));
        assertEquals(1, delivered.size());
        assertEquals("b-svc", delivered.get(0).getService());
        assertEquals("b-1.0", delivered.get(0).getServiceVersion());
    }

    @Test
    public void theHighestPriorityCompletionWinsImmediatelyAndCancelsTheRest() {
        check(checker(banner("a", new int[]{22}, 70), banner("b", new int[]{22}, 60), banner("c", new int[]{}, 50)), 22);

        answer(tx.connFor("a"), "a-2.0");

        assertEquals(1, delivered.size());
        assertEquals("a-svc", delivered.get(0).getService());
        assertTrue(tx.connFor("b").context().isTerminated(), "b is cancelled");
        assertTrue(tx.connFor("c").context().isTerminated(), "c is cancelled");
        assertFalse(tx.connFor("a").context().isTerminated() && delivered.isEmpty());

        answer(tx.connFor("b"), "b-late");
        assertEquals(1, delivered.size(), "a cancelled loser never delivers");
    }

    @Test
    public void whenEveryCandidateFailsTheResultIsNoneIdentifiedWithTheWellKnownName() {
        check(checker(banner("a", new int[]{22}, 70), banner("b", new int[]{22}, 60)), 22);

        silence(tx.connFor("a"));
        assertEquals(0, delivered.size());
        silence(tx.connFor("b"));

        assertEquals(1, delivered.size());
        ProbeResult r = delivered.get(0);
        assertFalse(r.isComplete());
        assertEquals("ssh", r.getService(), "port 22's well-known name is the fallback label");
        assertEquals("a, b", r.getServiceFact("probes-tried"));
        assertTrue(r.getNote().startsWith("no-probe-identified; 2 probe(s) tried: a, b"), r.getNote());
    }

    @Test
    public void aTimeoutOnEveryCandidateAlsoResolvesToNoneIdentified() {
        check(checker(banner("a", new int[]{22}, 70), banner("b", new int[]{22}, 60)), 22);
        // fire every live wait window: both connects time out
        while (clock.latestLive() != null && clock.latestLive().delayMs < 30_000) {
            clock.fireLatest();
        }
        assertEquals(1, delivered.size());
        assertFalse(delivered.get(0).isComplete());
    }

    @Test
    public void noApplicableCandidateDeliversNoneIdentifiedWithoutOpeningAnything() {
        check(checker(banner("ssh", new int[]{22}, 65)).matchPorts(true), 22);
        // now the transport-mismatch case
        ProbeChecker c = checker(banner("dns", "dns", new int[]{53}, 60, false, "udp"));
        List<ProbeResult> got = new ArrayList<>();
        c.check("127.0.0.1", 53, "tcp", new CallableConsumerTask<ProbeResult>().setConsumer(got::add));
        assertEquals(1, got.size());
        assertFalse(got.get(0).isComplete());
        assertEquals("dns", got.get(0).getService());
        assertEquals("", got.get(0).getServiceFact("probes-tried") == null ? "" : got.get(0).getServiceFact("probes-tried"));
        assertEquals(1, tx.connections.size(), "only the first checker opened a connection");
    }

    @Test
    public void aCandidateWhoseLaunchThrowsCountsAsIncompleteAndTheRestStillRun() {
        tx.failOpen = new IllegalStateException("scripted launch failure");
        check(checker(banner("a", new int[]{22}, 70), banner("b", new int[]{22}, 60)), 22);
        assertEquals(1, delivered.size(), "both launches failed synchronously → none identified");
        assertFalse(delivered.get(0).isComplete());
    }

    // ---------------------------------------------------------------- match-all

    @Test
    public void checkAllReturnsEveryCompletionInPriorityOrder() {
        ProbeChecker c = checker(banner("a", new int[]{22}, 70), banner("b", new int[]{22}, 60), banner("c", new int[]{}, 50));
        c.checkAll("127.0.0.1", 22, "tcp", new CallableConsumerTask<List<ProbeResult>>().setConsumer(deliveredAll::add));
        assertEquals(3, tx.connections.size());

        answer(tx.connFor("c"), "c-1");
        silence(tx.connFor("b"));
        assertEquals(0, deliveredAll.size(), "match-all waits for every candidate");
        answer(tx.connFor("a"), "a-1");

        assertEquals(1, deliveredAll.size());
        List<ProbeResult> all = deliveredAll.get(0);
        assertEquals(2, all.size());
        assertEquals("a-svc", all.get(0).getService());
        assertEquals("c-svc", all.get(1).getService());
    }

    @Test
    public void checkAllWithNoCompletionIsASingleNoneIdentified() {
        ProbeChecker c = checker(banner("a", new int[]{22}, 70));
        c.checkAll("127.0.0.1", 22, "tcp", new CallableConsumerTask<List<ProbeResult>>().setConsumer(deliveredAll::add));
        silence(tx.connFor("a"));
        assertEquals(1, deliveredAll.size());
        assertEquals(1, deliveredAll.get(0).size());
        assertFalse(deliveredAll.get(0).get(0).isComplete());
    }

    private static List<String> names(List<ProbeDefinition> defs) {
        List<String> out = new ArrayList<>();
        for (ProbeDefinition d : defs) {
            out.add(d.getName());
        }
        return out;
    }
}
