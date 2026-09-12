package io.xlogistx.nosneak.nmap;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.server.net.ssl.SSLConfigInt;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.net.IPAddress;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * A single non-blocking TCP-connect port probe (nmap {@code -sT} style). Reports exactly once,
 * fully event-driven: no blocking sockets, its own deadlines armed on the scheduler it is handed.
 * <p>
 * <b>Classification</b> (the v1 table, restored): a completed connect is {@link PortState#OPEN}
 * with reason {@code connected} — it is a full three-way handshake, not a SYN/ACK, so the old
 * {@code syn-ack} label was a lie. A refusal ({@link ConnectException} or "refused") is
 * {@link PortState#CLOSED}/{@code conn-refused}; a reset is CLOSED/{@code reset}; "unreachable"
 * or "no route" is {@link PortState#FILTERED}/{@code no-route}; the deadline is
 * FILTERED/{@code timeout}; and <em>anything else</em> is FILTERED with the exception's class
 * name as the reason. The old shape defaulted the unknown case to CLOSED, which reported a
 * reachable-and-refusing port for any error it had never seen.
 * <p>
 * <b>Banner and RTT on the connection already open.</b> {@link Result#rttMs} is the connect time.
 * With {@code grabBanner} the socket stays open for a short bounded window after the connect
 * (at most one second, never longer than the probe timeout) and whatever the server volunteers
 * is captured — capped at 1024 bytes, ISO-8859-1, CR/LF trimmed — then the probe completes on
 * the first of: bytes received, window elapsed, peer closed. Protocols that wait for the client
 * to speak (HTTP, TLS) volunteer nothing and pay exactly the window. A peer that resets or
 * closes during the window does not un-open the port: the connect already succeeded.
 * <p>
 * <b>TTL is never set here.</b> A connect scan works above the IP layer; the SYN/ACK's TTL is
 * consumed by the kernel and is not observable through a {@code SocketChannel}. Only a raw
 * capture could report it, and raw capture is out of scope for this scanner.
 */
public class PortScanCallback extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(PortScanCallback.class).setEnabled(false);

    /** Longest the socket stays open waiting for a volunteered banner. */
    public static final long BANNER_WINDOW_MS = 1_000;
    /** Most banner bytes kept; the rest of a chatty greeting is discarded. */
    public static final int BANNER_CAP = 1024;

    /** What one probe found. {@code banner} is null unless the server volunteered bytes. */
    public record Result(PortState state, String reason, long rttMs, String banner) { }

    private final Consumer<Result> onResult;
    private final ScheduledExecutorService scheduler;
    private final int timeoutSec;
    private final boolean grabBanner;
    private final long startNanos = System.nanoTime();
    private final AtomicBoolean done = new AtomicBoolean(false);
    private final AtomicBoolean connected = new AtomicBoolean(false);
    private final ByteArrayOutputStream bannerBytes = new ByteArrayOutputStream();
    private volatile long rttMs = -1;
    private volatile ScheduledFuture<?> deadline;
    private volatile ScheduledFuture<?> bannerWindow;

    /**
     * State-only probe, no banner window: connect completes the probe at once. This is the
     * shape host discovery's TCP-ping wants — it only needs OPEN-or-CLOSED.
     *
     * @param scheduler arms the FILTERED deadline — injected rather than looked up statically, so
     *                  the probe times out on the same pools its {@code NIOSocket} was built with
     */
    public PortScanCallback(ScheduledExecutorService scheduler, IPAddress address, int timeoutSec,
                            Consumer<PortState> onState) {
        this(scheduler, address, timeoutSec, false, r -> onState.accept(r.state()));
    }

    /**
     * @param grabBanner keep the socket open for {@link #BANNER_WINDOW_MS} after a connect and
     *                   capture what the server volunteers
     */
    public PortScanCallback(ScheduledExecutorService scheduler, IPAddress address, int timeoutSec,
                            boolean grabBanner, Consumer<Result> onResult) {
        super(address);
        this.scheduler = scheduler;
        this.timeoutSec = Math.max(timeoutSec, 1);
        this.grabBanner = grabBanner;
        this.onResult = onResult;
        // FILTERED deadline: fires if neither connect nor refusal arrives.
        this.deadline = scheduler.schedule(
                () -> finish(PortState.FILTERED, "timeout"), this.timeoutSec, TimeUnit.SECONDS);
    }

    /**
     * The IP this probe was aimed at — the address the target resolved to at construction —
     * or null if there is none. Available before the connect, so a host's {@code ip} can be
     * recorded by whichever unit is built first, whatever the outcome.
     */
    public String remoteIp() {
        java.net.InetSocketAddress a = getRemoteAddress();
        return a != null && a.getAddress() != null ? a.getAddress().getHostAddress() : null;
    }

    @Override
    protected void connectedFinished() throws IOException {
        if (done.get() || !connected.compareAndSet(false, true)) {
            return;
        }
        rttMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
        if (!grabBanner) {
            finish(PortState.OPEN, "connected");
            return;
        }
        // The connect answered the question; the FILTERED deadline must not fire now. Replace
        // it with the banner window, which completes OPEN whatever the server does.
        cancel(deadline);
        deadline = null;
        long window = Math.min(BANNER_WINDOW_MS, timeoutSec * 1_000L);
        bannerWindow = scheduler.schedule(
                () -> finish(PortState.OPEN, "connected"), window, TimeUnit.MILLISECONDS);
    }

    @Override
    protected void sslUpgraded(SSLConfigInt sslConfig) throws IOException {
        // never upgraded: a connect scan speaks no TLS
    }

    @Override
    public void exception(Throwable e) {
        if (connected.get()) {
            // A reset or close during the banner window: the port was open, and stays open.
            finish(PortState.OPEN, "connected");
            return;
        }
        Classification c = classify(e);
        finish(c.state, c.reason);
    }

    /** Only ever called by the selector after a connect, with whatever the server volunteered. */
    @Override
    public void accept(ByteBuffer buffer) {
        if (!grabBanner || !connected.get() || done.get() || buffer == null) {
            return;
        }
        synchronized (bannerBytes) {
            while (buffer.hasRemaining() && bannerBytes.size() < BANNER_CAP) {
                bannerBytes.write(buffer.get());
            }
        }
        finish(PortState.OPEN, "connected");
    }

    /**
     * The scan was cancelled. A port whose connect already succeeded is still reported OPEN —
     * that fact was observed and stays true — while one still waiting on the wire is reported
     * {@link PortState#FILTERED}/{@code cancelled}, since nothing was learned about it. Idempotent
     * with every other completion: the deadline, the banner window and this all race through one
     * exactly-once {@code finish}, so the socket is closed and the result delivered once.
     */
    public void abort() {
        if (connected.get()) {
            finish(PortState.OPEN, "connected");
        } else {
            finish(PortState.FILTERED, "cancelled");
        }
    }

    /** The classification table, exposed for the unit test; pure. */
    static Classification classify(Throwable e) {
        if (e instanceof ConnectException) {
            return new Classification(PortState.CLOSED, "conn-refused");
        }
        String m = e != null && e.getMessage() != null ? e.getMessage().toLowerCase() : "";
        if (m.contains("refused")) {
            return new Classification(PortState.CLOSED, "conn-refused");
        }
        if (m.contains("reset")) {
            return new Classification(PortState.CLOSED, "reset");
        }
        if (m.contains("unreachable") || m.contains("no route")) {
            return new Classification(PortState.FILTERED, "no-route");
        }
        String name = e == null ? "unknown" : e.getClass().getSimpleName();
        return new Classification(PortState.FILTERED, "error:" + name);
    }

    record Classification(PortState state, String reason) { }

    private void finish(PortState state, String reason) {
        if (!done.compareAndSet(false, true)) {
            return;
        }
        cancel(deadline);
        deadline = null;
        cancel(bannerWindow);
        bannerWindow = null;
        String banner;
        synchronized (bannerBytes) {
            banner = bannerBytes.size() == 0 ? null
                    : cleanBanner(bannerBytes.toString(StandardCharsets.ISO_8859_1));
        }
        try { SharedIOUtil.close(this); } catch (Exception ignored) { }
        try { onResult.accept(new Result(state, reason, rttMs, banner)); } catch (Exception ignored) { }
    }

    private static void cancel(ScheduledFuture<?> f) {
        if (f != null) {
            try { f.cancel(false); } catch (Exception ignored) { }
        }
    }

    /** Trim, collapse CR/LF runs to a single space, drop anything unprintable. */
    static String cleanBanner(String raw) {
        String s = raw.replaceAll("[\\r\\n]+", " ").replaceAll("[^\\x20-\\x7E]", "").trim();
        return s.isEmpty() ? null : s;
    }
}
