package io.xlogistx.nosneak.v2.nmap;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * A single non-blocking TCP-connect port probe (nmap {@code -sT} style): a successful
 * connect ⇒ {@link PortState#OPEN}, a refused connection ⇒ {@link PortState#CLOSED}, no
 * response within the deadline ⇒ {@link PortState#FILTERED}. Reports its state exactly once.
 * Fully event-driven — no blocking sockets, its own deadline armed on
 * the scheduler it is handed.
 */
public class PortScanCallback extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(PortScanCallback.class).setEnabled(false);

    private final Consumer<PortState> onResult;
    private final AtomicBoolean done = new AtomicBoolean(false);
    private volatile ScheduledFuture<?> deadline;

    /**
     * @param scheduler arms the FILTERED deadline — injected rather than looked up statically, so
     *                  the probe times out on the same pools its {@code NIOSocket} was built with
     */
    public PortScanCallback(ScheduledExecutorService scheduler, IPAddress address, int timeoutSec,
                            Consumer<PortState> onResult) {
        super(address);
        this.onResult = onResult;
        // FILTERED deadline: fires if neither connect nor refusal arrives.
        this.deadline = scheduler.schedule(
                () -> finish(PortState.FILTERED), Math.max(timeoutSec, 1), TimeUnit.SECONDS);
    }

    @Override
    protected void connectedFinished() throws IOException {
        finish(PortState.OPEN);
    }

    @Override
    public void exception(Throwable e) {
        // Refused/reset ⇒ CLOSED (host reachable); no-route/unreachable ⇒ FILTERED.
        String m = e != null && e.getMessage() != null ? e.getMessage().toLowerCase() : "";
        finish(m.contains("unreachable") || m.contains("no route") ? PortState.FILTERED : PortState.CLOSED);
    }

    @Override
    public void accept(SelectionKey key) {
        // Connect-only scan: we never read.
    }

    @Override
    public void accept(ByteBuffer buffer) {
    }

    private void finish(PortState state) {
        if (!done.compareAndSet(false, true)) {
            return;
        }
        ScheduledFuture<?> d = deadline;
        if (d != null) {
            deadline = null;
            try { d.cancel(false); } catch (Exception ignored) { }
        }
        try { SharedIOUtil.close(this); } catch (Exception ignored) { }
        try { onResult.accept(state); } catch (Exception ignored) { }
    }
}
