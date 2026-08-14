package io.xlogistx.nosneak.app.ui.assistant;

import io.xlogistx.nosneak.ai.AICredentialSource;
import io.xlogistx.nosneak.app.ui.utility.Session;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.security.CredentialInfo;
import org.zoxweb.shared.security.SubjectAPIKey;

import java.util.ArrayList;
import java.util.List;

/**
 * Lets the {@code ai-assistant} module reach NoSneak's API keys without depending on this one —
 * it implements the assistant's credential interface over a {@link io.xlogistx.nosneak.app.ui.utility.Session}.
 * <p>
 * The assistant <b>never stores a secret</b>: keys stay ordinary NoSneak credentials owned by the
 * session, and the assistant only records which ones it may use (the {@code assistant-enabled}
 * property) plus its own provider rows. A key is used only once the subject picks it — nothing is
 * auto-enabled.
 * <p>
 * Key identity is always the <b>GUID</b>, never the name, which is editable.
 */
public class SessionAICredentialSource implements AICredentialSource {
    private final Session session;

    public SessionAICredentialSource(Session session) {
        this.session = session;
    }


    @Override
    public List<APIKey<String>> APIKeys() {
        List<APIKey<String>> out = new ArrayList<>();

        for (CredentialInfo ci : session.getAllCredentialForUserByType(CredentialInfo.Type.API_KEY)) {
            if (ci instanceof SubjectAPIKey k) out.add(k);
        }
        return out;

    }

    @Override
    public List<APIKey<String>> enabledAPIKeys() {
        List<APIKey<String>> out = new ArrayList<>();
        for (APIKey<String> k : APIKeys()) {
            if (session.isAssistantEnabled(k)) out.add(k);
        }
        return out;
    }

    @Override
    public void setEnabled(APIKey<String> key, boolean enabled) {
        session.setAssistantEnabled(key, enabled);
    }

    @Override
    public APIKey<String> addAPIKey(String label, String description, String provider, String baseURL,
                                    String authType, String headerName, String secret) throws SecurityException {
        APIKey<String> key = session.storeAPIKey(label, description, "", "", secret,
                provider, baseURL, authType, headerName, true);
        session.setAssistantEnabled(key, true);
        return key;
    }
}
