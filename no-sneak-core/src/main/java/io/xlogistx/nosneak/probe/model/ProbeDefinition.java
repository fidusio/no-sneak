package io.xlogistx.nosneak.probe.model;

import java.util.Map;

/**
 * A JSON-declared protocol probe: a named state machine that interrogates an
 * open {@code ip:port} to produce a structured
 * {@link io.xlogistx.nosneak.probe.ProbeResult}. Deserialized from a
 * {@code probes/*.json} resource via {@code GSONUtil.fromJSONDefault}.
 * <p>
 * The graph is data; the executable primitives referenced by each state's
 * {@code action} come from a fixed, trusted Java library
 * ({@link io.xlogistx.nosneak.probe.action}). A definition therefore configures
 * behaviour but can never introduce new executable code.
 */
public class ProbeDefinition {

    private String name;
    private String service;
    private String transport;   // "tcp" | "udp"
    private int[] ports;
    private int priority = 50;  // higher = preferred when several definitions match a port
    private String start;       // id of the initial state
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

    public String getStart() {
        return start;
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
