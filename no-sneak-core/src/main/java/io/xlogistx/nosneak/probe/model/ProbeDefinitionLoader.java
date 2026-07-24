package io.xlogistx.nosneak.probe.model;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.util.GSONUtil;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Loads and validates {@link ProbeDefinition}s from JSON resources on the
 * classpath (bundled under {@code /probes/}).
 * <p>
 * Loading is fail-fast: a definition with a dangling transition, a missing
 * start state, an unknown action, or no reachable terminal state is rejected
 * with an {@link IllegalArgumentException} rather than blowing up mid-scan.
 */
public final class ProbeDefinitionLoader {

    public static final LogWrapper log = new LogWrapper(ProbeDefinitionLoader.class).setEnabled(false);

    /** The action names recognised by the fixed action library. */
    public static final Set<String> KNOWN_ACTIONS = new HashSet<>(Arrays.asList(
            "connect", "send", "expect", "starttls", "tls-handshake",
            "pqc-check", "tls-facts", "record", "reconnect", "done", "fail"));

    /** Actions that terminate the state machine (no outgoing transitions required). */
    public static final Set<String> TERMINAL_ACTIONS = new HashSet<>(Arrays.asList("done", "fail"));

    /** The probe definitions bundled with this module. */
    public static final String[] BUNDLED = {
            "/probes/https-pqc.json",
            "/probes/smtp-starttls-pqc.json",
            "/probes/mongodb.json",
            "/probes/imaps-pqc.json",
            "/probes/imap-starttls-pqc.json"
    };

    private ProbeDefinitionLoader() {
    }

    /**
     * Load and validate a single definition from a classpath resource.
     *
     * @throws IllegalArgumentException if the resource is missing or invalid
     */
    public static ProbeDefinition load(String resourcePath) {
        String json = readResource(resourcePath);
        ProbeDefinition def;
        try {
            def = GSONUtil.fromJSONDefault(json, ProbeDefinition.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Malformed probe JSON at " + resourcePath + ": " + e.getMessage(), e);
        }
        validate(def, resourcePath);
        return def;
    }

    /**
     * Load and validate a single definition from a filesystem file (as opposed to
     * a bundled classpath resource).
     *
     * @throws IllegalArgumentException if the file is unreadable or invalid
     */
    public static ProbeDefinition loadFile(String filePath) {
        String json;
        try {
            json = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath)),
                    java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot read probe file " + filePath + ": " + e.getMessage(), e);
        }
        ProbeDefinition def;
        try {
            def = GSONUtil.fromJSONDefault(json, ProbeDefinition.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Malformed probe JSON at " + filePath + ": " + e.getMessage(), e);
        }
        validate(def, filePath);
        return def;
    }

    /** Load, validate, and priority-sort a set of filesystem probe files. */
    public static List<ProbeDefinition> loadFiles(List<String> filePaths) {
        List<ProbeDefinition> out = new ArrayList<>();
        for (String p : filePaths) {
            out.add(loadFile(p));
        }
        out.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));
        return out;
    }

    /**
     * Load and validate every bundled definition, sorted by descending priority
     * (so the dispatcher can pick the most specific probe for a port first).
     */
    public static List<ProbeDefinition> loadBundled() {
        return loadAll(BUNDLED);
    }

    public static List<ProbeDefinition> loadAll(String... resourcePaths) {
        List<ProbeDefinition> out = new ArrayList<>();
        for (String path : resourcePaths) {
            out.add(load(path));
        }
        out.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));
        return out;
    }

    // ==================== Validation ====================

    /**
     * Structural validation of a loaded definition: start state present, every
     * transition target resolvable, every action known, and at least one
     * terminal state reachable from start.
     */
    public static void validate(ProbeDefinition def, String source) {
        if (def == null) {
            throw new IllegalArgumentException("Null probe definition from " + source);
        }
        if (def.getName() == null || def.getName().isEmpty()) {
            throw new IllegalArgumentException("Probe " + source + " has no name");
        }
        Map<String, ProbeState> states = def.getStates();
        if (states == null || states.isEmpty()) {
            throw new IllegalArgumentException("Probe " + def.getName() + " has no states");
        }
        String start = def.getStart();
        if (start == null || !states.containsKey(start)) {
            throw new IllegalArgumentException("Probe " + def.getName()
                    + " start state '" + start + "' is not defined");
        }

        for (Map.Entry<String, ProbeState> e : states.entrySet()) {
            String id = e.getKey();
            ProbeState st = e.getValue();
            String action = st.getAction();
            if (action == null || !KNOWN_ACTIONS.contains(action)) {
                throw new IllegalArgumentException("Probe " + def.getName() + " state '" + id
                        + "' has unknown action '" + action + "'");
            }
            if (st.getOn() != null) {
                for (Map.Entry<String, String> t : st.getOn().entrySet()) {
                    if (!states.containsKey(t.getValue())) {
                        throw new IllegalArgumentException("Probe " + def.getName() + " state '" + id
                                + "' transition '" + t.getKey() + "' points at undefined state '"
                                + t.getValue() + "'");
                    }
                }
            } else if (!TERMINAL_ACTIONS.contains(action)) {
                throw new IllegalArgumentException("Probe " + def.getName() + " non-terminal state '"
                        + id + "' (action=" + action + ") has no transitions");
            }
        }

        if (!reachesTerminal(def, start)) {
            throw new IllegalArgumentException("Probe " + def.getName()
                    + " has no terminal (done/fail) state reachable from '" + start + "'");
        }
    }

    /** BFS from {@code start}; true iff some reachable state uses a terminal action. */
    private static boolean reachesTerminal(ProbeDefinition def, String start) {
        Set<String> seen = new HashSet<>();
        java.util.Deque<String> queue = new java.util.ArrayDeque<>();
        queue.add(start);
        seen.add(start);
        while (!queue.isEmpty()) {
            ProbeState st = def.state(queue.poll());
            if (st == null) {
                continue;
            }
            if (TERMINAL_ACTIONS.contains(st.getAction())) {
                return true;
            }
            if (st.getOn() != null) {
                for (String target : st.getOn().values()) {
                    if (seen.add(target)) {
                        queue.add(target);
                    }
                }
            }
        }
        return false;
    }

    // ==================== Resource IO ====================

    private static String readResource(String resourcePath) {
        try (InputStream in = ProbeDefinitionLoader.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IllegalArgumentException("Probe resource not found on classpath: " + resourcePath);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed reading probe resource " + resourcePath + ": " + e.getMessage(), e);
        }
    }
}
