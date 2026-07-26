package io.xlogistx.nosneak.v2.tls;

import io.xlogistx.nosneak.v2.tls.PQCConnectionHelper.PQCHandshakeState;
import org.zoxweb.server.fsm.State;
import org.zoxweb.server.fsm.StateMachine;
import org.zoxweb.server.fsm.Trigger;
import org.zoxweb.server.fsm.TriggerConsumer;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.logging.LogWrapper;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import static io.xlogistx.nosneak.v2.tls.PQCConnectionHelper.PQCHandshakeState.*;

/**
 * Non-blocking Bouncy Castle TLS/PQC handshake driven by zoxweb-core's trigger-based
 * {@link StateMachine} — the {@code MonoStateMachine}-free replacement for the v1
 * {@code PQCSSLStateMachine}. Same step logic (START → NEED_WRITE → NEED_READ →
 * FINISHED / CLOSED), now dispatched as {@link TriggerConsumer}s keyed by the step
 * name (mirroring {@code org.zoxweb.server.net.ssl.SSLStateMachine}).
 * <p>
 * BC non-blocking mode: {@link PQCSessionConfig#beginHandshake()} sends ClientHello;
 * output bytes are drained to the channel in NEED_WRITE; inbound network bytes are fed
 * via {@link #processIncomingData}; completion is signalled to the caller's callback in
 * FINISHED. An inline executor keeps every step on the calling (selector/scheduler)
 * thread, which {@code ProbeContext} already serialises.
 */
public class PQCHandshakeStateMachine extends StateMachine<PQCSessionConfig>
        implements PQCConnectionHelper {

    public static final LogWrapper log = new LogWrapper(PQCHandshakeStateMachine.class).setEnabled(false);

    private static final AtomicLong COUNTER = new AtomicLong();

    private final PQCSessionConfig config;

    public PQCHandshakeStateMachine(PQCSessionConfig config) {
        super("pqc-handshake-" + COUNTER.incrementAndGet(), (Runnable r) -> r.run()); // inline, sequential
        this.config = config;
        config.connectionHelper = this;
        register(step(START, this::handleStart));
        register(step(NEED_WRITE, this::handleNeedWrite));
        register(step(NEED_READ, this::handleNeedRead));
        register(step(FINISHED, this::handleFinished));
        register(step(CLOSED, this::handleClosed));
        setConfig(config);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private State step(PQCHandshakeState s, Consumer<Consumer<PQCSessionConfig>> handler) {
        State st = new State(s.name());
        st.register(new TriggerConsumer<Consumer<PQCSessionConfig>>(s.name()) {
            @Override
            public void accept(Consumer<PQCSessionConfig> cb) {
                handler.accept(cb);
            }
        });
        return st;
    }

    @Override
    public void publish(PQCHandshakeState state, Consumer<PQCSessionConfig> callback) {
        if (!isClosed()) {
            publishSync(new Trigger<Consumer<PQCSessionConfig>>(this, state, getCurrentState(), callback));
        }
    }

    @Override
    public PQCSessionConfig getConfig() {
        return config;
    }

    @Override
    public void close() {
        super.close();
        config.close();
    }

    // ==================== Step handlers ====================

    /** START — initialize the BC protocol and send ClientHello. */
    private void handleStart(Consumer<PQCSessionConfig> callback) {
        try {
            config.initProtocol();
            config.beginHandshake(); // sends ClientHello into BC output
            if (config.getAvailableOutputBytes() > 0) {
                publish(NEED_WRITE, callback);
            } else {
                publish(NEED_READ, callback);
            }
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("START error: " + e.getMessage());
            publish(CLOSED, callback);
        }
    }

    /** NEED_WRITE — drain BC output (ciphertext) to the network channel. */
    private void handleNeedWrite(Consumer<PQCSessionConfig> callback) {
        if (config.isClosed()) {
            publish(CLOSED, callback);
            return;
        }
        try {
            int available = config.getAvailableOutputBytes();
            if (available > 0) {
                byte[] outputData = new byte[available];
                int read = config.readOutput(outputData, 0, available);
                if (read > 0) {
                    ByteBufferUtil.write(config.channel, ByteBuffer.wrap(outputData, 0, read), false);
                }
            }
            if (config.isHandshaking()) {
                publish(NEED_READ, callback);
            } else if (config.handshakeComplete.get()) {
                publish(FINISHED, callback);
            } else if (config.handshakeStarted.get()) {
                config.handshakeComplete.set(true);
                publish(FINISHED, callback);
            } else {
                publish(NEED_READ, callback);
            }
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("NEED_WRITE error: " + e.getMessage());
            publish(CLOSED, callback);
        }
    }

    /** NEED_READ — parked; server bytes arrive later via {@link #processIncomingData}. */
    private void handleNeedRead(Consumer<PQCSessionConfig> callback) {
        if (config.isClosed()) {
            publish(CLOSED, callback);
        }
    }

    /** FINISHED — notify the caller's callback (which harvests facts from the client). */
    private void handleFinished(Consumer<PQCSessionConfig> callback) {
        if (callback != null) {
            try {
                callback.accept(config);
            } catch (Exception e) {
                if (log.isEnabled()) log.getLogger().info("FINISHED callback error: " + e.getMessage());
            }
        }
    }

    /** CLOSED — tear down the session. */
    private void handleClosed(Consumer<PQCSessionConfig> callback) {
        config.close();
    }

    /** Feed inbound network bytes into the BC pump; advance to write/finish as needed. */
    public void processIncomingData(ByteBuffer data, Consumer<PQCSessionConfig> callback) {
        if (config.isClosed()) {
            return;
        }
        try {
            if (data != null && data.hasRemaining()) {
                byte[] bytes = new byte[data.remaining()];
                data.get(bytes);
                config.offerInput(bytes, 0, bytes.length);
                if (config.getAvailableOutputBytes() > 0) {
                    publish(NEED_WRITE, callback);
                } else if (!config.isHandshaking()) {
                    config.handshakeComplete.set(true);
                    publish(FINISHED, callback);
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("processIncomingData error: " + e.getMessage());
        }
    }
}
