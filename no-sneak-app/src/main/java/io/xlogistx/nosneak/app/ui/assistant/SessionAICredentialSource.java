package io.xlogistx.nosneak.app.ui.assistant;

import io.xlogistx.nosneak.ai.AICredentialSource;
import io.xlogistx.nosneak.app.ui.utility.Session;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.security.CredentialInfo;
import org.zoxweb.shared.security.SubjectAPIKey;

import java.util.ArrayList;
import java.util.List;

public class SessionAICredentialSource implements AICredentialSource {
    private final Session session;

    public SessionAICredentialSource(Session session) {
        this.session = session;
    }


    @Override
    public List<APIKey<String>> APIKeys() {
        List<APIKey<String>> out = new ArrayList<>();

        for (CredentialInfo ci : session.getAllCredentialForUserByType(CredentialInfo.Type.API_KEY)) {

            SubjectAPIKey k = (SubjectAPIKey) ci;

            out.add(k);
        }
        return out;

    }
}
