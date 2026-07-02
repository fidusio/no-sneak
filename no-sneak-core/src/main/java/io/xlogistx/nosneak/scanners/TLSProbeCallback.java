package io.xlogistx.nosneak.scanners;

import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsFatalAlert;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.net.IPAddress;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Base class for NIO TLS probe callbacks.
 * Handles the non-blocking TLS handshake lifecycle using Bouncy Castle's
 * TlsClientProtocol in non-blocking mode.
 * <p>
 * Subclasses implement:
 * <ul>
 *   <li>{@link #createTlsClient()} - provide the configured TLS client</li>
 *   <li>{@link #onProbeSuccess()} - called when handshake succeeds</li>
 *   <li>{@link #onProbeFailure(Throwable)} - called when handshake fails</li>
 * </ul>
 * <p>
 * NOTE: the NIOSocket connection timeout only covers the TCP connect phase
 * (it is cancelled by {@code finishConnecting} as soon as the socket connects).
 * Once connected, a server that accepts the TCP connection but never sends a
 * usable TLS response (no ServerHello, no alert) would otherwise stall this
 * probe forever, and since the probe never reports a result the parent
 * {@link PQCScanCallback} pendingCount never reaches zero and the whole scan
 * hangs. To prevent that, this class arms its own post-connect handshake
 * timeout via the task scheduler (event-driven, non-blocking).
 */
public abstract class TLSProbeCallback extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(TLSProbeCallback.class).setEnabled(false);

    protected TlsClientProtocol protocol;
    private final ByteBuffer readBuffer = ByteBufferUtil.allocateByteBuffer(16384);

    // Terminal-transition guard: success/failure callback is invoked exactly
    // once even if the NIO selector thread and the scheduler timeout race.
    private final AtomicBoolean done = new AtomicBoolean(false);

    private volatile SelectionKey selectionKey;
    private volatile ScheduledFuture<?> timeoutAppointment;

    protected TLSProbeCallback(IPAddress address) {
        super(address);
        closeableDelegate.setDelegate(()->{
            cancelTimeout();
            if (selectionKey != null) {
                selectionKey.cancel();
            }
            SharedIOUtil.close(getChannel());
            ByteBufferUtil.cache(readBuffer);
        });
    }

    /**
     * Create the TLS client to use for this probe.
     */
    protected abstract DefaultTlsClient createTlsClient();

    /**
     * Called when the TLS handshake completes successfully.
     */
    protected abstract void onProbeSuccess();

    /**
     * Called when the TLS handshake fails.
     *
     * @param cause the failure cause (may be TlsFatalAlert for expected rejections)
     */
    protected abstract void onProbeFailure(Throwable cause);

    @Override
    protected void connectedFinished() throws IOException {
        if (done.get()) return;

        try {
            // Initialize BC TLS protocol in non-blocking mode (no-arg constructor)
            protocol = new TlsClientProtocol();
            DefaultTlsClient client = createTlsClient();

            // Begin handshake - this generates ClientHello
            protocol.connect(client);

            // Flush ClientHello to network
            flushOutput();

            // Arm the post-connect handshake timeout. The NIOSocket connect
            // timeout is already cancelled by now, so without this a silent
            // server would hang the probe (and the parent scan) indefinitely.
            armTimeout();
        } catch (TlsFatalAlert e) {
            if (complete()) onProbeFailure(e);
        } catch (Exception e) {
            if (complete()) onProbeFailure(e);
        }
    }

    @Override
    public void accept(SelectionKey key) {
        if (done.get()) return;

        if(this.selectionKey != null && this.selectionKey != key) {
            log.getLogger().info("Key Mismatch current " + this.selectionKey + " new key " + key);

        }

        this.selectionKey = key;

        try {
            if (key.isReadable() && protocol != null) {
                SocketChannel channel = (SocketChannel) key.channel();
                readBuffer.clear();
                int bytesRead = channel.read(readBuffer);

                if (bytesRead == -1) {
                    key.cancel();
                    if (complete()) onProbeFailure(new IOException("Connection closed by peer"));
                    return;
                }

                if (bytesRead > 0) {
                    readBuffer.flip();
                    byte[] bytes = new byte[readBuffer.remaining()];
                    readBuffer.get(bytes);

                    protocol.offerInput(bytes, 0, bytes.length);

                    // Flush any response data (e.g., Finished message)
                    flushOutput();

                    // Check if handshake is done
                    if (!protocol.isHandshaking()) {
                        if (complete()) onProbeSuccess();
                    }
                }
            }
        } catch (TlsFatalAlert e) {
            // Expected for probe rejections (e.g., handshake_failure, protocol_version)
            key.cancel();
            if (complete()) onProbeFailure(e);
        } catch (Exception e) {
            key.cancel();
            if (complete()) onProbeFailure(e);
        }
    }

    @Override
    public void accept(ByteBuffer buffer) {
        // Delegate to SelectionKey-based accept
    }

    @Override
    public void exception(Throwable e) {
        if (complete()) onProbeFailure(e);
    }

    /**
     * Flush BC TLS output to the network channel.
     */
    protected void flushOutput() throws IOException {
        int available = protocol.getAvailableOutputBytes();
        if (available > 0) {
            byte[] outputData = new byte[available];
            int read = protocol.readOutput(outputData, 0, available);
            if (read > 0) {
                ByteBuffer writeBuffer = ByteBuffer.wrap(outputData, 0, read);
                ByteBufferUtil.write(getChannel(), writeBuffer, false);
            }
        }
    }

    /**
     * Arm the post-connect handshake timeout using the shared task scheduler.
     * Event-driven (no blocking thread), consistent with the pure-NIO design.
     */
    private void armTimeout() {
        timeoutAppointment = TaskUtil.defaultTaskScheduler().schedule(() -> {
            if (complete()) {
                onProbeFailure(new IOException(
                        "TLS probe handshake timeout after " + timeoutInSec() + "s (no usable server response)"));
            }
        }, timeoutInSec(), TimeUnit.SECONDS);
    }

    private void cancelTimeout() {
        ScheduledFuture<?> a = timeoutAppointment;
        if (a != null) {
            timeoutAppointment = null;
            try {
                // cancel(false): never interrupt the scheduler worker. If the
                // timeout already started, it can't be stopped anyway; if it
                // hasn't, this just dequeues it.
                a.cancel(false);
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Transition this probe to its terminal state exactly once.
     *
     * @return {@code true} if this call performed the transition (the caller
     *         must invoke exactly one of onProbeSuccess/onProbeFailure);
     *         {@code false} if the probe was already completed.
     */
    private boolean complete() {
        if (!done.compareAndSet(false, true)) {
            return false;
        }
        cancelTimeout();
        try {
            if (protocol != null) {
                protocol.close();
            }
        } catch (Exception ignored) {
        }
        try {
            close();
        } catch (Exception ignored) {
        }
        return true;
    }

}
