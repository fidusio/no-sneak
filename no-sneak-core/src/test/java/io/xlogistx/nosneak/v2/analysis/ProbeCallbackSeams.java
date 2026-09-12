package io.xlogistx.nosneak.v2.analysis;

import java.io.IOException;

/**
 * Completes an enumeration child (a version, cipher or group handshake) with no socket, the way
 * the peer would: {@code accept} is the terminal transition {@link TLSProbeCallback} makes when a
 * handshake completes, {@code reject} the one NIOSocket makes when the peer refuses. The accept
 * seams are package-private on the callbacks; this public helper is the one door the runtime
 * tests use.
 */
public final class ProbeCallbackSeams {

    private ProbeCallbackSeams() {
    }

    /** The server completed a handshake at the offered version. */
    public static void accept(VersionProbeCallback probe) {
        probe.finishAccepted();
    }

    /** The server completed a handshake and picked {@code selectedSuite} from the offer. */
    public static void accept(CipherProbeCallback probe, int selectedSuite) {
        probe.finishAccepted(selectedSuite);
    }

    /** The server completed a TLS 1.3 handshake on the offered group. */
    public static void accept(GroupProbeCallback probe) {
        probe.finishAccepted();
    }

    /** The server refused (alert, reset or silence): the public failure path, as NIOSocket reports it. */
    public static void reject(TLSProbeCallback probe) {
        probe.exception(new IOException("rejected by the scripted peer"));
    }
}
