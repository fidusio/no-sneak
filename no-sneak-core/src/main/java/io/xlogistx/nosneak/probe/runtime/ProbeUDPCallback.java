package io.xlogistx.nosneak.probe.runtime;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.DataPacket;
import org.zoxweb.server.net.common.UDPSessionCallback;

import java.io.IOException;

/**
 * Deferred UDP transport seam for the probe framework (QUIC/DTLS actions are
 * out of scope for this increment). It extends {@link UDPSessionCallback} with
 * the same ephemeral-bind pattern as {@code UDPPortScanCallback} so the wiring
 * exists; datagram-driven probe actions and per-remote-address state keying are
 * left for a follow-up. Each datagram would be delivered via
 * {@code accept(DataPacket)}, keyed by {@link DataPacket} remote address into a
 * per-target {@link ProbeSession}.
 */
public class ProbeUDPCallback extends UDPSessionCallback {

    public static final LogWrapper log = new LogWrapper(ProbeUDPCallback.class).setEnabled(false);
    private static final int BUFFER_SIZE = 2048;

    public ProbeUDPCallback() {
        super(null, 0, BUFFER_SIZE); // bind to an ephemeral local port
    }

    @Override
    public void accept(DataPacket dp) throws IOException {
        // Deferred: route datagram to the ProbeSession keyed by dp.getAddress().
        if (log.isEnabled() && dp != null) {
            log.getLogger().info("UDP probe datagram (deferred): " + dp);
        }
    }

    @Override
    public void sslHandshakeSuccessful() throws IOException {
        // Not applicable to UDP (no TLS handshake on this transport).
    }

    @Override
    public void exception(Throwable t) {
        if (log.isEnabled() && t != null) {
            log.getLogger().info("UDP probe exception (deferred): " + t);
        }
    }
}
