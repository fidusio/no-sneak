package io.xlogistx.nosneak.probe.action;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Name &rarr; {@link Action} lookup for the fixed action library. Populated once
 * with the built-in primitives; actions are stateless singletons shared across
 * all sessions.
 */
public final class ActionRegistry {

    private static final Map<String, Action> ACTIONS = new ConcurrentHashMap<>();

    static {
        register(new ConnectAction());
        register(new SendAction());
        register(new ExpectAction());
        register(new StartTLSAction());
        register(new TLSHandshakeAction());
        register(new PQCCheckAction());
        register(new TLSFactsAction());
        register(new RecordAction());
        register(new ReconnectAction());
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
