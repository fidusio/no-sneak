package io.xlogistx.nosneak.runtime;

import io.xlogistx.nosneak.nmap.ScanGate;
import io.xlogistx.nosneak.tls.PQCSessionConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.server.net.common.UDPSessionCallback;
import org.zoxweb.server.net.ssl.SSLConfigInt;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The child-socket accounting of {@link GatedProbeTransport} on its own: a candidate's own
 * connection passes through (its start already holds the slot), an enumeration child is admitted
 * past a full cap and counted, every counted child is released exactly once — on abort or when
 * the parent finishes — and a failed child open hands its slot straight back.
 */
public class GatedProbeTransportTest {

    /** A key that is nothing but an identity. */
    static final class FakeKey extends SelectionKey {
        @Override public SelectableChannel channel() { return null; }
        @Override public Selector selector() { return null; }
        @Override public boolean isValid() { return true; }
        @Override public void cancel() { }
        @Override public int interestOps() { return 0; }
        @Override public SelectionKey interestOps(int ops) { return this; }
        @Override public int readyOps() { return 0; }
    }

    /** Records opens and aborts; hands out a fresh key per open. */
    static final class RecordingTransport implements ProbeTransport {
        final List<TCPSessionCallback> opened = new ArrayList<>();
        final List<SelectionKey> aborted = new ArrayList<>();
        IOException failOpen;

        @Override
        public SelectionKey open(TCPSessionCallback cb, int timeoutSec) throws Exception {
            if (failOpen != null) throw failOpen;
            opened.add(cb);
            return new FakeKey();
        }

        @Override
        public SelectionKey open(TCPSessionCallback cb) throws Exception {
            return open(cb, 0);
        }

        @Override
        public SelectionKey openDatagram(UDPSessionCallback cb) {
            return new FakeKey();
        }

        @Override
        public void write(ProbeTCPCallback cb, byte[] data) { }

        @Override
        public TlsSession startTls(ProbeTCPCallback cb, InetSocketAddress sni, boolean classicalOnly,
                                   Consumer<PQCSessionConfig> onTransition) {
            return new TlsSession(null, null);
        }

        @Override
        public void abort(SelectionKey key) {
            aborted.add(key);
        }
    }

    /** A callback that only records the failure it was handed. */
    static final class Cb extends TCPSessionCallback {
        Throwable failure;
        Cb() { super(new IPAddress("127.0.0.1", 1)); }
        @Override protected void connectedFinished() { }
        @Override protected void sslUpgraded(SSLConfigInt sslConfig) { }
        @Override public void exception(Throwable e) { failure = e; }
        @Override public void accept(ByteBuffer buffer) { }
    }

    private RecordingTransport delegate;
    private ScanGate gate;
    private ManualScheduler clock;

    @BeforeEach
    public void fresh() {
        delegate = new RecordingTransport();
        clock = new ManualScheduler();
        gate = new ScanGate(clock, 1, 0);   // one slot
    }

    @Test
    public void theCandidatesOwnConnectionPassesThroughUncounted() throws Exception {
        GatedProbeTransport a = new GatedProbeTransport(delegate, gate);
        assertNotNull(a.open(new Cb(), 3), "opened at once, with a key");
        assertEquals(0, gate.inFlight(), "its slot is the one its start was admitted on, not a second one");
        assertEquals(0, a.outstanding());
    }

    @Test
    public void aChildIsAdmittedPastAFullCapAndCountedUntilReleased() throws Exception {
        gate.submit(() -> { });                   // something else holds the only slot
        assertEquals(1, gate.inFlight());

        GatedProbeTransport a = new GatedProbeTransport(delegate, gate);
        SelectionKey child = a.open(new Cb());    // an enumeration child
        assertNotNull(child, "a probe never waits on itself");
        assertEquals(2, gate.inFlight(), "the child is counted even though the cap is 1");
        assertEquals(1, a.outstanding());

        a.abort(child);
        assertEquals(1, gate.inFlight());
        assertEquals(0, a.outstanding());
        a.releaseAll();
        assertEquals(1, gate.inFlight(), "an aborted child is not released twice");
    }

    @Test
    public void childrenStillOpenWhenTheParentFinishesAreReleasedThen() throws Exception {
        GatedProbeTransport a = new GatedProbeTransport(delegate, gate);
        a.open(new Cb());
        a.open(new Cb());
        assertEquals(2, gate.inFlight());
        a.releaseAll();
        assertEquals(0, gate.inFlight());
        assertEquals(0, a.outstanding());
        assertThrows(IOException.class, () -> a.open(new Cb()), "nothing may be opened after the finish");
    }

    @Test
    public void aFailedChildOpenReleasesItsSlotAndReportsThroughTheCallback() throws Exception {
        GatedProbeTransport a = new GatedProbeTransport(delegate, gate);
        delegate.failOpen = new IOException("refused");
        Cb cb = new Cb();
        assertNull(a.open(cb));
        assertEquals("refused", cb.failure.getMessage(), "the failure reaches the callback, as NIOSocket's would");
        assertEquals(0, gate.inFlight(), "a child that failed to open holds nothing");
        assertEquals(0, a.outstanding());
    }

    @Test
    public void abortOfAnUnknownKeyIsForwardedAndCountsNothing() {
        GatedProbeTransport a = new GatedProbeTransport(delegate, gate);
        SelectionKey k = new FakeKey();
        a.abort(k);
        assertEquals(1, delegate.aborted.size());
        assertEquals(0, gate.inFlight());
    }
}
