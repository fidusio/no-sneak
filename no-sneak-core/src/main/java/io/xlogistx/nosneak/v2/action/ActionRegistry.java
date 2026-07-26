package io.xlogistx.nosneak.v2.action;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Name &rarr; {@link Action} lookup for the fixed action library. Populated once with
 * the built-in primitives; actions are stateless singletons shared across all runs.
 * Grows per phase as new actions (TLS, PQC, STARTTLS, fan-out, analysis) are added.
 */
public final class ActionRegistry {

    private static final Map<String, Action> ACTIONS = new ConcurrentHashMap<>();

    static {
        register(new ConnectAction());
        register(new SendAction());
        register(new ExpectAction());
        register(new ReconnectAction());
        register(new StartTLSAction());
        register(new TLSConnectAction());
        register(new TLSHandshakeAction());
        register(new PQCCheckAction());
        register(new TLSFactsAction());
        register(new CertChainAction());
        register(new RevocationAction());
        register(new EnumerateVersionsAction());
        register(new EnumerateCiphersAction());
        register(new RecordAction());
        register(new TerminalAction("done", true));
        register(new TerminalAction("fail", false));
    }

    private ActionRegistry() {
    }

    public static void register(Action action) {
        ACTIONS.put(action.name(), action);
    }

    public static Action get(String name) {
        Action a = ACTIONS.get(name);
        if (a == null) {
            throw new IllegalStateException("No action registered for '" + name + "'");
        }
        return a;
    }
}
