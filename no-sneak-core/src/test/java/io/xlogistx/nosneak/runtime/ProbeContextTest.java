package io.xlogistx.nosneak.runtime;

import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.result.ProbeResult;
import io.xlogistx.nosneak.runtime.ScriptedTransport.Conn;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.net.IPAddress;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static io.xlogistx.nosneak.runtime.ScriptedTransport.connected;
import static io.xlogistx.nosneak.runtime.ScriptedTransport.inbound;
import static io.xlogistx.nosneak.runtime.ScriptedTransport.peerClosed;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives the probe state machine through every branch with no socket and no real timer
 * (PENDING-ISSUES P11). The bundled definitions are used as-is, so a change to {@code ssh.json}
 * or {@code http.json} that breaks a transition fails here rather than on a live host.
 */
public class ProbeContextTest {

    private static final IPAddress TARGET = new IPAddress("127.0.0.1", 22);
    private static final int TIMEOUT = 3;

    private ScriptedTransport tx;
    private ManualScheduler clock;

    @BeforeEach
    public void fresh() {
        tx = new ScriptedTransport();
        clock = new ManualScheduler();
    }

    static ProbeDefinition bundled(String name) {
        for (ProbeDefinition d : ProbeDefinitionLoader.loadBundled()) {
            if (name.equals(d.getName())) {
                return d;
            }
        }
        throw new IllegalStateException("no bundled probe " + name);
    }

    static ProbeDefinition parse(String json, String name) {
        return ProbeDefinitionLoader.parse(json, name);
    }

    private ProbeContext start(ProbeDefinition def) {
        ProbeContext ctx = tx.newContext(clock, new IPAddress("127.0.0.1", def.getPorts().length > 0 ? def.getPorts()[0] : 22), def, TIMEOUT);
        ctx.start();
        return ctx;
    }

    // ---------------------------------------------------------------- the happy paths

    @Test
    public void sshBannerMatchCapturesTheVersionAndCompletes() {
        ProbeContext ctx = start(bundled("ssh"));
        Conn c = tx.last();
        assertEquals(TIMEOUT, c.timeoutSec);
        assertEquals("connect", ctx.currentStateId());

        connected(c);
        assertEquals("banner", ctx.currentStateId());
        assertTrue(ctx.isArmed());

        inbound(c, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11\r\n");

        assertEquals(1, tx.delivered.size());
        ProbeResult r = tx.delivered.get(0);
        assertTrue(r.isComplete());
        assertEquals("ssh", r.getService());
        assertEquals("OpenSSH_8.2p1 Ubuntu-4ubuntu0.11", r.getServiceVersion());
        assertTrue(r.getNote().contains("ssh"));
        assertTrue(r.isSuccess());
        assertNull(r.getErrorMessage());
        assertTrue(ctx.isTerminated());
        assertEquals(0, clock.liveCount(), "every timer is cancelled at delivery");
    }

    @Test
    public void httpSendsATemplatedRequestAndCapturesTheServerHeader() {
        ProbeContext ctx = start(bundled("http"));
        Conn c = tx.last();
        assertEquals(80, c.port());

        connected(c);
        // send fires synchronously, so the engine is already waiting for the response
        assertEquals("response", ctx.currentStateId());
        String request = c.writtenText();
        assertTrue(request.startsWith("GET / HTTP/1.1\r\n"), request);
        assertTrue(request.contains("Host: 127.0.0.1\r\n"), "the template must expand the hostname: " + request);

        inbound(c, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n");

        ProbeResult r = tx.delivered.get(0);
        assertTrue(r.isComplete());
        assertEquals("nginx/1.24.0", r.getServiceVersion());
        assertTrue(r.getNote().contains("http-1.1-server-header"));
    }

    @Test
    public void aBannerThatArrivesInTwoChunksStillMatches() {
        ProbeContext ctx = start(bundled("ftp"));
        Conn c = tx.last();
        connected(c);
        inbound(c, "22");
        assertEquals(0, tx.delivered.size(), "half a status code is not a match");
        inbound(c, "0 ProFTPD 1.3.8 Server ready\r\n");
        assertEquals("ProFTPD 1.3.8 Server ready", tx.delivered.get(0).getServiceVersion());
    }

    // ---------------------------------------------------------------- the failure branches

    @Test
    public void peerCloseAfterUnmatchedDataIsNomatch() {
        start(bundled("ssh"));
        Conn c = tx.last();
        connected(c);
        inbound(c, "not an ssh banner\r\n");
        assertEquals(0, tx.delivered.size());

        peerClosed(c);

        ProbeResult r = tx.delivered.get(0);
        assertFalse(r.isComplete());
        assertEquals("fail", r.getNote());
        assertNull(r.getServiceVersion());
    }

    @Test
    public void peerCloseBeforeAnyDataIsError() {
        ProbeContext ctx = start(bundled("ssh"));
        Conn c = tx.last();
        connected(c);
        peerClosed(c);
        assertFalse(tx.delivered.get(0).isComplete());
        assertTrue(ctx.isTerminated());
    }

    @Test
    public void theConnectWaitTimesOutIntoTheStatesTimeoutOutcome() {
        ProbeContext ctx = start(bundled("ssh"));
        assertEquals("connect", ctx.currentStateId());
        clock.fireLatest(); // the connect window
        assertFalse(tx.delivered.get(0).isComplete());
        assertEquals("fail", tx.delivered.get(0).getNote());
    }

    @Test
    public void theExpectWaitTimesOutIntoTheStatesTimeoutOutcome() {
        ProbeContext ctx = start(bundled("ssh"));
        connected(tx.last());
        assertEquals("banner", ctx.currentStateId());
        clock.fireLatest(); // the expect window
        assertFalse(tx.delivered.get(0).isComplete());
    }

    @Test
    public void theOverallWatchdogDeliversIncompleteWhateverTheStateIs() {
        ProbeContext ctx = start(bundled("ssh"));
        connected(tx.last());
        ManualScheduler.Task watchdog = clock.tasks.get(0); // armed first, in start()
        assertEquals(Math.max(TIMEOUT * 4, 30) * 1000L, watchdog.delayMs);

        watchdog.run();

        ProbeResult r = tx.delivered.get(0);
        assertFalse(r.isComplete());
        assertTrue(r.getNote().contains("overall-timeout"), r.getNote());
        assertTrue(ctx.isTerminated());
    }

    @Test
    public void anOutcomeTheDefinitionDoesNotMapEndsTheProbeIncomplete() {
        // connect maps only "connected": a launch failure fires "error", which has nowhere to go.
        ProbeDefinition def = parse("{\"name\":\"gap\",\"service\":\"x\",\"ports\":[1],\"start\":\"connect\","
                + "\"states\":{\"connect\":{\"action\":\"connect\",\"on\":{\"connected\":\"done\"}},"
                + "\"done\":{\"action\":\"done\"}}}", "gap");
        tx.failOpen = new IllegalStateException("no route");

        start(def);

        ProbeResult r = tx.delivered.get(0);
        assertFalse(r.isComplete());
        assertTrue(r.getNote().startsWith("unhandled-outcome:error@connect"), r.getNote());
    }

    @Test
    public void aFailedWriteIsTheSendStatesErrorOutcome() {
        tx.failWrite = true;
        ProbeContext ctx = start(bundled("http"));
        connected(tx.last());
        ProbeResult r = tx.delivered.get(0);
        assertFalse(r.isComplete());
        assertEquals("fail", r.getNote());
    }

    // ---------------------------------------------------------------- multi-connection and upgrade

    @Test
    public void reconnectOpensASecondConnectionOnTheAlternatePortAndRecordsTheFirst() {
        ProbeDefinition def = parse("{\"name\":\"twice\",\"service\":\"x\",\"ports\":[25],\"start\":\"connect\","
                + "\"states\":{\"connect\":{\"action\":\"connect\",\"on\":{\"connected\":\"again\",\"error\":\"fail\",\"timeout\":\"fail\"}},"
                + "\"again\":{\"action\":\"reconnect\",\"port\":8025,\"on\":{\"connected\":\"done\",\"error\":\"fail\",\"timeout\":\"fail\"}},"
                + "\"done\":{\"action\":\"done\"},\"fail\":{\"action\":\"fail\"}}}", "twice");
        ProbeContext ctx = start(def);
        Conn first = tx.last();
        assertEquals(25, first.port());

        connected(first);
        assertEquals(2, tx.connections.size());
        Conn second = tx.last();
        assertEquals(8025, ctx.currentPort());
        assertEquals("again", ctx.currentStateId());

        connected(second);
        ProbeResult r = tx.delivered.get(0);
        assertTrue(r.isComplete());
        List<String> outcomes = new ArrayList<>();
        for (ProbeResult.ConnectionTrace t : r.getConnections()) {
            outcomes.add(t.index + ":" + t.port + ":" + t.outcome);
        }
        assertTrue(outcomes.contains("1:25:reconnect"), outcomes.toString());
        assertTrue(outcomes.contains("2:8025:done"), outcomes.toString());
    }

    @Test
    public void starttlsReadyStartsTheHandshakeAndAHandshakeTimeoutRecordsIt() {
        ProbeContext ctx = start(bundled("smtp-starttls-pqc"));
        Conn c = tx.last();
        connected(c);
        inbound(c, "220 mail.example ESMTP\r\n");
        assertEquals("ehloResp", ctx.currentStateId());
        assertTrue(c.writtenText().contains("EHLO 127.0.0.1\r\n"), c.writtenText());

        inbound(c, "250-mail.example\r\n250-STARTTLS\r\n250 OK\r\n");
        assertEquals("starttls", ctx.currentStateId());
        assertTrue(c.writtenText().endsWith("STARTTLS\r\n"), c.writtenText());
        assertTrue(ctx.isUpgrade());

        inbound(c, "220 go ahead\r\n");
        assertEquals("tls", ctx.currentStateId());
        assertEquals(1, tx.tlsStarts.size(), "ready must start exactly one handshake");
        assertEquals("127.0.0.1", tx.tlsStarts.get(0).sni.getHostString());
        assertFalse(tx.tlsStarts.get(0).classicalOnly, "mode pqc offers hybrids");

        clock.fireLatest(); // the handshake window elapses on the scripted transport
        ProbeResult r = tx.delivered.get(0);
        assertTrue(r.isComplete(), "an advertised-but-failed STARTTLS is still an identification");
        assertTrue(r.getNote().contains("starttls-advertised-handshake-failed"), r.getNote());
        assertEquals("smtp", r.getService());
    }

    // ---------------------------------------------------------------- exactly-once and the monitor

    @Test
    public void cancelMidFlightDeliversNothingAndIsIdempotent() {
        ProbeContext ctx = start(bundled("ssh"));
        Conn c = tx.last();
        connected(c);

        ctx.cancel();
        ctx.cancel();
        inbound(c, "SSH-2.0-late\r\n");
        clock.tasks.forEach(ManualScheduler.Task::run);

        assertTrue(ctx.isTerminated());
        assertEquals(0, tx.delivered.size(), "a cancelled context never delivers");
    }

    @Test
    public void deliverIsExactlyOnceEvenWhenATerminalIsReachedAgain() {
        ProbeContext ctx = start(bundled("ssh"));
        Conn c = tx.last();
        connected(c);
        inbound(c, "SSH-2.0-x\r\n");
        assertEquals(1, tx.delivered.size());

        ctx.deliver(false, "again");
        inbound(c, "SSH-2.0-y\r\n");
        clock.tasks.forEach(ManualScheduler.Task::run);

        assertEquals(1, tx.delivered.size());
        assertTrue(tx.delivered.get(0).isComplete(), "the first delivery stands");
    }

    @Test
    public void aStaleTimerFromAnEarlierWaitCannotResolveALaterOne() {
        ProbeContext ctx = start(bundled("ssh"));
        Conn c = tx.last();
        ManualScheduler.Task connectWindow = clock.latestLive();

        connected(c); // resolves the connect window and arms the expect window (a new generation)
        assertTrue(connectWindow.isCancelled());
        assertEquals("banner", ctx.currentStateId());

        connectWindow.run(); // the cancel lost the race: the old timer still fires

        assertEquals("banner", ctx.currentStateId(), "a stale generation must be ignored");
        assertTrue(ctx.isArmed());
        assertEquals(0, tx.delivered.size());
    }

    @Test
    public void theUserCallbackRunsOutsideTheContextMonitor() {
        AtomicBoolean heldMonitor = new AtomicBoolean(true);
        ProbeContext[] holder = new ProbeContext[1];
        ProbeContext ctx = tx.newContext(clock, TARGET, bundled("ssh"), TIMEOUT,
                r -> heldMonitor.set(Thread.holdsLock(holder[0])));
        holder[0] = ctx;
        ctx.start();
        Conn c = tx.last();
        connected(c);

        inbound(c, "SSH-2.0-x\r\n"); // delivery happens inside this call, after the monitor is released

        assertFalse(heldMonitor.get(), "P10: the callback must not run under the context monitor");
    }

    @Test
    public void theUserCallbackRunsOutsideTheMonitorOnATimerToo() {
        AtomicBoolean heldMonitor = new AtomicBoolean(true);
        ProbeContext[] holder = new ProbeContext[1];
        ProbeContext ctx = tx.newContext(clock, TARGET, bundled("ssh"), TIMEOUT,
                r -> heldMonitor.set(Thread.holdsLock(holder[0])));
        holder[0] = ctx;
        ctx.start();

        clock.fireLatest();

        assertFalse(heldMonitor.get());
        assertNotNull(ctx);
    }

    @Test
    public void aCallbackThatCancelsAnotherContextDoesNotDeadlockOrLeak() {
        // The FirstSweep shape: the winner's callback cancels the losers. With the callback
        // outside the monitor this is plain sequential code; it must also leave the loser silent.
        ProbeContext loser = tx.newContext(clock, TARGET, bundled("ssh"), TIMEOUT);
        loser.start();
        Conn loserConn = tx.last();
        ProbeContext winner = tx.newContext(clock, TARGET, bundled("ssh"), TIMEOUT, r -> loser.cancel());
        winner.start();
        Conn winnerConn = tx.last();

        connected(winnerConn);
        inbound(winnerConn, "SSH-2.0-win\r\n");

        assertTrue(loser.isTerminated());
        connected(loserConn);
        inbound(loserConn, "SSH-2.0-lose\r\n");
        assertEquals(0, tx.delivered.size(), "the cancelled loser never delivers");
    }

    // ---------------------------------------------------------------- the error surface and the budget

    @Test
    public void aFailedProbeCarriesSuccessFalseAndTheTerminalNoteAsTheError() {
        start(bundled("ssh"));
        Conn c = tx.last();
        connected(c);
        peerClosed(c);

        ProbeResult r = tx.delivered.get(0);
        assertFalse(r.isComplete());
        assertFalse(r.isSuccess());
        assertEquals("fail", r.getErrorMessage());
        assertEquals("false", r.toNVGenericMap().getValue("success"));
    }

    @Test
    public void theOverallWatchdogCarriesItsMarkerAsTheError() {
        start(bundled("ssh"));
        connected(tx.last());
        clock.tasks.get(0).run(); // the watchdog, armed first in start()
        ProbeResult r = tx.delivered.get(0);
        assertFalse(r.isSuccess());
        assertEquals("overall-timeout", r.getErrorMessage());
    }

    @Test
    public void anActionFailureNoteIsAppendedToTheError() {
        ProbeContext ctx = start(bundled("ssh"));
        ctx.noteFailure("expect: java.lang.IllegalStateException: boom"); // what ProbeActionConsumer records
        clock.fireLatest(); // the connect window → "timeout" → fail
        ProbeResult r = tx.delivered.get(0);
        assertFalse(r.isSuccess());
        assertEquals("fail: expect: java.lang.IllegalStateException: boom", r.getErrorMessage());
    }

    @Test
    public void aCompletedProbeHasNoErrorEvenAfterANotedFailure() {
        ProbeContext ctx = start(bundled("ssh"));
        ctx.noteFailure("something recovered from");
        Conn c = tx.last();
        connected(c);
        inbound(c, "SSH-2.0-OpenSSH_9.6\r\n");
        ProbeResult r = tx.delivered.get(0);
        assertTrue(r.isSuccess(), "reaching done is success, whatever happened en route");
        assertNull(r.getErrorMessage());
    }

    @Test
    public void aDefinitionMayDeclareItsOwnOverallBudget() {
        ProbeDefinition def = parse("{\"name\":\"budget\",\"service\":\"x\",\"ports\":[1],\"overallTimeoutSec\":7,"
                + "\"start\":\"connect\",\"states\":{\"connect\":{\"action\":\"connect\",\"on\":{\"connected\":\"done\","
                + "\"error\":\"fail\",\"timeout\":\"fail\"}},\"done\":{\"action\":\"done\"},\"fail\":{\"action\":\"fail\"}}}",
                "budget");
        start(def);
        assertEquals(7_000L, clock.tasks.get(0).delayMs, "the declared budget replaces max(4 x timeout, 30)");

        tx = new ScriptedTransport();
        clock = new ManualScheduler();
        start(bundled("tls-scan"));
        assertEquals(90_000L, clock.tasks.get(0).delayMs, "the bundled deep scan declares 90 s");
    }
}
