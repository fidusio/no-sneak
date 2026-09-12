package io.xlogistx.nosneak.nmap;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.DataPacket;
import org.zoxweb.server.net.common.UDPSessionCallback;
import org.zoxweb.server.net.ssl.SSLConfigInt;
import org.zoxweb.shared.io.SharedIOUtil;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * One non-blocking UDP port probe (nmap {@code -sU} semantics), on its own ephemeral datagram
 * socket <em>connected</em> to the target so the kernel's ICMP errors are attributable to it.
 * Reports exactly once, fully event-driven: no blocking sockets, its own deadlines armed on the
 * scheduler it is handed.
 * <p>
 * <b>Classification.</b> Any datagram back is {@link PortState#OPEN}/{@code udp-response}, with
 * the RTT and the first bytes as a banner. An ICMP port-unreachable, which a connected channel
 * surfaces as {@link PortUnreachableException} on the next receive or send, is
 * {@link PortState#CLOSED}/{@code port-unreach}. Any other unreachable is
 * {@link PortState#FILTERED}/{@code no-route}. Silence for the whole timeout is
 * {@link PortState#OPEN_FILTERED}/{@code no-response} — UDP cannot tell an open service that
 * ignored us from a firewall that dropped us, so it does not pretend to.
 * <p>
 * <b>One retransmit</b>, at half the timeout, before silence is declared. Besides giving a busy
 * service a second chance, the resend is what surfaces a pending ICMP error on platforms whose
 * selector does not wake for one: the send itself then throws, and the port reads closed at half
 * the budget instead of open|filtered at the end of it.
 */
public class UdpScanCallback extends UDPSessionCallback {

    public static final LogWrapper log = new LogWrapper(UdpScanCallback.class).setEnabled(false);

    /** Most reply bytes kept as a banner. */
    public static final int BANNER_CAP = 256;

    /** What one probe found. {@code banner} is null unless the server sent printable bytes. */
    public record Result(PortState state, String reason, long rttMs, String banner) { }

    record Classification(PortState state, String reason) { }

    private final ScheduledExecutorService scheduler;
    private final InetSocketAddress target;
    private final byte[] payload;
    private final int timeoutSec;
    private final Consumer<Result> onResult;
    private final AtomicBoolean done = new AtomicBoolean(false);
    private volatile long startNanos = System.nanoTime();
    private volatile ScheduledFuture<?> retransmit;
    private volatile ScheduledFuture<?> deadline;

    /**
     * @param scheduler arms the retransmit and the deadline — injected, so the probe times out on
     *                  the same pools its {@code NIOSocket} was built with
     * @param target    the remote to connect the datagram socket to (resolved)
     * @param payload   the datagram to send, from {@link UdpProbePayloads#forPort}
     */
    public UdpScanCallback(ScheduledExecutorService scheduler, InetSocketAddress target, byte[] payload,
                           int timeoutSec, Consumer<Result> onResult) {
        super(null, 0, 2048); // executor null: the selector thread hands us the key directly
        this.scheduler = scheduler;
        this.target = target;
        this.payload = payload == null ? new byte[0] : payload;
        this.timeoutSec = Math.max(timeoutSec, 1);
        this.onResult = onResult;
    }

    /**
     * The kickoff {@code NIOSocket} guarantees before any read dispatch: connect the channel to
     * the target, send the first datagram, arm the timers. A failure here propagates so the
     * registration is torn down; the caller classifies it with {@link #classify}.
     */
    @Override
    public int connected(SelectionKey key) {
        int ops = super.connected(key);
        try {
            DatagramChannel ch = getChannel();
            ch.connect(target);
            startNanos = System.nanoTime();
            send();
        } catch (IOException e) {
            // The base signature declares no IOException; NIOSocket catches RuntimeException
            // around connected(), cancels the key, closes the channel and rethrows to the
            // caller, whose classify() unwraps this.
            throw new UncheckedIOException(e);
        }
        arm();
        return ops;
    }

    /** Arms the half-way retransmit and the full-budget deadline. Package-private for the test. */
    void arm() {
        long budgetMs = timeoutSec * 1_000L;
        retransmit = scheduler.schedule(this::retransmit, budgetMs / 2, TimeUnit.MILLISECONDS);
        deadline = scheduler.schedule(this::expire, budgetMs, TimeUnit.MILLISECONDS);
    }

    private void send() throws IOException {
        DatagramChannel ch = getChannel();
        if (ch == null) {
            return;
        }
        synchronized (this) {
            ch.write(ByteBuffer.wrap(payload));
        }
    }

    /** The one resend. A send that throws is an ICMP error the selector did not deliver. */
    void retransmit() {
        if (done.get()) {
            return;
        }
        try {
            send();
        } catch (Throwable t) {
            onReceiveError(t);
        }
    }

    /** Silence for the whole budget. */
    void expire() {
        finish(PortState.OPEN_FILTERED, "no-response", null);
    }

    /**
     * The scan was cancelled: nothing was heard, so the port is reported
     * {@link PortState#FILTERED}/{@code cancelled} — not open|filtered, which would claim the
     * whole silence budget was waited out. Exactly-once with the timers and the ingress paths.
     */
    public void abort() {
        finish(PortState.FILTERED, "cancelled", null);
    }

    /** Read dispatch from the selector: drain what arrived, classify the first thing that matters. */
    @Override
    public void accept(SelectionKey key) {
        DatagramChannel ch = (DatagramChannel) key.channel();
        ByteBuffer buf = ByteBuffer.allocate(getBufferSize());
        try {
            SocketAddress from = ch.receive(buf);
            if (from != null) {
                buf.flip();
                byte[] bytes = new byte[buf.remaining()];
                buf.get(bytes);
                onDatagram(bytes);
            }
        } catch (Throwable t) {
            onReceiveError(t);
        }
    }

    /** Not used: {@link #accept(SelectionKey)} reads the channel itself so it can see the ICMP error. */
    @Override
    public void accept(DataPacket<?> dataPacket) {
        if (dataPacket == null) {
            return;
        }
        ByteBuffer buf = dataPacket.getIOBuffers().getInBuffer();
        byte[] bytes = new byte[buf == null ? 0 : buf.remaining()];
        if (buf != null) {
            buf.get(bytes);
        }
        onDatagram(bytes);
    }

    @Override
    public void exception(Throwable e) {
        onReceiveError(e);
    }

    @Override
    public void sslHandshakeSuccessful(SSLConfigInt config) {
        // not applicable to UDP
    }

    /** A datagram came back: the port is open. Package-private for the test. */
    void onDatagram(byte[] bytes) {
        finish(PortState.OPEN, "udp-response", banner(bytes));
    }

    /** An error on the channel: an ICMP message, or a dead socket. Package-private for the test. */
    void onReceiveError(Throwable t) {
        Classification c = classify(t);
        finish(c.state, c.reason, null);
    }

    /** The classification table; pure. */
    static Classification classify(Throwable t) {
        if (t instanceof UncheckedIOException u && u.getCause() != null) {
            t = u.getCause();
        }
        if (t instanceof PortUnreachableException) {
            return new Classification(PortState.CLOSED, "port-unreach");
        }
        String m = t != null && t.getMessage() != null ? t.getMessage().toLowerCase() : "";
        if (m.contains("port unreachable") || m.contains("connection reset")
                || m.contains("forcibly closed")) {
            // Windows reports the ICMP port-unreachable on a connected UDP socket as a reset.
            return new Classification(PortState.CLOSED, "port-unreach");
        }
        if (m.contains("unreachable") || m.contains("no route")) {
            return new Classification(PortState.FILTERED, "no-route");
        }
        String name = t == null ? "unknown" : t.getClass().getSimpleName();
        return new Classification(PortState.FILTERED, "error:" + name);
    }

    static String banner(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        int n = Math.min(bytes.length, BANNER_CAP);
        String s = new String(bytes, 0, n, StandardCharsets.ISO_8859_1)
                .replaceAll("[\\r\\n]+", " ").replaceAll("[^\\x20-\\x7E]", "").trim();
        return s.isEmpty() ? null : s;
    }

    private void finish(PortState state, String reason, String banner) {
        if (!done.compareAndSet(false, true)) {
            return;
        }
        long rtt = state == PortState.OPEN || state == PortState.CLOSED
                ? TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos) : -1;
        cancel(retransmit);
        retransmit = null;
        cancel(deadline);
        deadline = null;
        try { SharedIOUtil.close(this); } catch (Exception ignored) { }
        try { onResult.accept(new Result(state, reason, rtt, banner)); } catch (Exception ignored) { }
    }

    private static void cancel(ScheduledFuture<?> f) {
        if (f != null) {
            try { f.cancel(false); } catch (Exception ignored) { }
        }
    }
}
