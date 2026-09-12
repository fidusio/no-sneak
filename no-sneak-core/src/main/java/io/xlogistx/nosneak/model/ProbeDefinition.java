package io.xlogistx.nosneak.model;

import java.util.Map;

/**
 * A JSON-declared protocol probe: a named state machine that interrogates an
 * open {@code ip:port} to produce a structured
 * {@link io.xlogistx.nosneak.result.ProbeResult}. Deserialized from a
 * {@code probes/*.json} resource via {@code GSONUtil.fromJSONDefault}.
 * <p>
 * The graph is data; the executable primitives referenced by each state's
 * {@code action} come from a fixed, trusted Java library
 * ({@link io.xlogistx.nosneak.action}). A definition therefore configures
 * behaviour but can never introduce new executable code.
 */
public class ProbeDefinition {

    private String name;
    private String service;
    private String transport;   // "tcp" | "udp"
    private int[] ports;
    private int priority = 50;  // higher = preferred when several definitions match a port
    // When true, this probe only runs on its declared ports and is NOT tried as a generic
    // fallback on other ports. Set it on ungated "any-TLS" catch-alls (e.g. https-pqc,
    // imaps-pqc) so they can't mislabel an arbitrary TLS service (Postgres-over-TLS, etc.).
    private boolean portScoped = false;
    private String start;       // id of the initial state
    // Overall watchdog for one run of this probe, in seconds. Null = the engine's formula,
    // max(4 x per-step timeout, 30 s). A deep scan (handshake + versions + ciphers + groups +
    // revocation) declares its own budget rather than inheriting a ceiling meant for a banner grab.
    private Integer overallTimeoutSec;
    private Map<String, ProbeState> states;

    public String getName() {
        return name;
    }

    public String getService() {
        return service;
    }

    public String getTransport() {
        return transport == null ? "tcp" : transport;
    }

    public int[] getPorts() {
        return ports;
    }

    public int getPriority() {
        return priority;
    }

    /**
     * If true, this probe runs only on its declared {@code ports} and is excluded from the generic
     * fallback tier (so an ungated any-TLS probe cannot claim an unrelated port).
     */
    public boolean isPortScoped() {
        return portScoped;
    }

    public String getStart() {
        return start;
    }

    /** Overall watchdog for a run of this probe, in seconds; null = {@code max(4 x timeout, 30)}. */
    public Integer getOverallTimeoutSec() {
        return overallTimeoutSec;
    }

    public Map<String, ProbeState> getStates() {
        return states;
    }

    public ProbeState state(String id) {
        return states == null ? null : states.get(id);
    }

    /**
     * Does this definition apply to the given port/transport?
     */
    public boolean matches(int port, String transport) {
        if (!getTransport().equalsIgnoreCase(transport)) {
            return false;
        }
        if (ports == null) {
            return false;
        }
        for (int p : ports) {
            if (p == port) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return "ProbeDefinition{name='" + name + "', service='" + service
                + "', transport='" + getTransport() + "', ports="
                + java.util.Arrays.toString(ports) + ", priority=" + priority + "}";
    }
}
