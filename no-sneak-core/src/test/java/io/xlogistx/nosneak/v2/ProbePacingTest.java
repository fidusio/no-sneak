package io.xlogistx.nosneak.v2;

import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.nmap.ScanGate;
import io.xlogistx.nosneak.v2.result.ProbeResult;
import io.xlogistx.nosneak.v2.runtime.ConnectionGate;
import io.xlogistx.nosneak.v2.runtime.GatedProbeTransport;
import io.xlogistx.nosneak.v2.runtime.ManualScheduler;
import io.xlogistx.nosneak.v2.runtime.ScriptedTransport;
import io.xlogistx.nosneak.v2.runtime.ScriptedTransport.Conn;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.task.CallableConsumerTask;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static io.xlogistx.nosneak.v2.ProbeCheckerTest.banner;
import static io.xlogistx.nosneak.v2.runtime.ScriptedTransport.connected;
import static io.xlogistx.nosneak.v2.runtime.ScriptedTransport.inbound;
import static io.xlogistx.nosneak.v2.runtime.ScriptedTransport.peerClosed;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PENDING-ISSUES P4: the probe stage's sockets count against the scan's in-flight cap. A checker
 * over a two-slot {@link ScanGate} with three candidates must never have more than two
 * connections open, and must hand every slot back when the sweep is over.
 */
public class ProbePacingTest {

    private ScriptedTransport tx;
    private ManualScheduler clock;
    private ScanGate gate;
    private final List<ProbeResult> delivered = new ArrayList<>();

    @BeforeEach
    public void fresh() {
        tx = new ScriptedTransport();
        clock = new ManualScheduler();
        gate = new ScanGate(clock, 2, 0);   // two in flight, no per-second pacing
        delivered.clear();
    }

    private GatedProbeTransport.Registry registry;

    /** The production factory shape over the scripted transport: a registry so cancels release. */
    private ProbeChecker.ContextFactory factory(ConnectionGate g) {
        registry = new GatedProbeTransport.Registry(g);
        return new ProbeChecker.ContextFactory() {
            @Override
            public io.xlogistx.nosneak.v2.runtime.ProbeContext create(
                    org.zoxweb.shared.net.IPAddress target, ProbeDefinition definition, int timeoutSec,
                    java.util.function.Consumer<ProbeResult> callback) {
                return registry.create(tx, clock, Runnable::run, target, definition, timeoutSec, callback);
            }

            @Override
            public void start(io.xlogistx.nosneak.v2.runtime.ProbeContext ctx) {
                registry.start(ctx);
            }

            @Override
            public void cancelled(io.xlogistx.nosneak.v2.runtime.ProbeContext ctx) {
                registry.cancelled(ctx);
            }
        };
    }

    private ProbeChecker checker(ProbeDefinition... defs) {
        List<ProbeDefinition> sorted = new ArrayList<>(List.of(defs));
        sorted.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));
        return new ProbeChecker(sorted, Runnable::run, factory(gate)).timeoutInSec(3);
    }

    private void check(ProbeChecker c) {
        c.check("127.0.0.1", 8080, new CallableConsumerTask<ProbeResult>().setConsumer(delivered::add));
    }

    @Test
    public void neverMoreThanTheCapInFlightAndTheThirdWaitsForASlot() {
        check(checker(banner("a", new int[]{8080}, 90), banner("b", new int[]{8080}, 80),
                      banner("c", new int[]{8080}, 70)));

        assertEquals(2, tx.connections.size(), "the third candidate is waiting for a slot");
        assertEquals(2, gate.inFlight());

        // Nobody answers on the first two; when the peer closes one, its slot frees and the third
        // candidate connects.
        Conn a = tx.connFor("a");
        connected(a);
        peerClosed(a);
        assertEquals(3, tx.connections.size(), "the freed slot admitted the waiting candidate");
        assertEquals(2, gate.inFlight());
        assertTrue(delivered.isEmpty(), "the election is still waiting on b and c");

        Conn b = tx.connFor("b");
        connected(b);
        peerClosed(b);
        Conn c = tx.connFor("c");
        connected(c);
        inbound(c, "OK 3.1\r\n");

        assertEquals(1, delivered.size());
        assertEquals("c-svc", delivered.get(0).getService());
        assertEquals(0, gate.inFlight(), "every slot handed back once the sweep is over");
    }

    @Test
    public void aWinnerCancelsTheWaitingCandidateWithoutItEverOpening() {
        check(checker(banner("a", new int[]{8080}, 90), banner("b", new int[]{8080}, 80),
                      banner("c", new int[]{8080}, 70)));
        assertEquals(2, tx.connections.size());

        Conn a = tx.connFor("a");
        connected(a);
        inbound(a, "OK 1.0\r\n");   // the highest priority completes: instant win

        assertEquals(1, delivered.size());
        assertEquals("a-svc", delivered.get(0).getService());
        assertEquals(2, tx.connections.size(), "the cancelled third candidate never opened a socket");
        assertEquals(0, gate.inFlight(), "the winner's, the cancelled loser's and the never-launched "
                + "candidate's slots are all back — a cancelled context delivers nothing, so the "
                + "registry hands them back");
        assertEquals(0, registry.liveCount(), "nothing left tracked");
    }

    @Test
    public void anUnlimitedGateBehavesLikeNoGate() {
        AtomicInteger releases = new AtomicInteger();
        ConnectionGate counting = new ConnectionGate() {
            @Override public void submit(Runnable launch) { launch.run(); }
            @Override public void submitNow(Runnable launch) { launch.run(); }
            @Override public void release() { releases.incrementAndGet(); }
        };
        ProbeChecker c = new ProbeChecker(List.of(banner("a", new int[]{8080}, 90)), Runnable::run,
                factory(counting)).timeoutInSec(3);
        check(c);
        assertEquals(1, tx.connections.size());
        Conn a = tx.last();
        connected(a);
        inbound(a, "OK 1.0\r\n");
        assertEquals(1, delivered.size());
        assertEquals(1, releases.get(), "one launch, one release");
    }
}
