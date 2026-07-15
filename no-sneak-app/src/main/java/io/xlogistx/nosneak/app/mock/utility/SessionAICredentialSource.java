package io.xlogistx.nosneak.app.mock.utility;

import agent.AICredential;
import agent.AICredentialSource;
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
    public List<AICredential> credentials() {
        List<AICredential> out = new ArrayList<>();
        for (CredentialInfo ci : session.getAllCredentialForUserByType(CredentialInfo.Type.API_KEY)) {

            SubjectAPIKey k = (SubjectAPIKey) ci;

            if (!session.isAIKey(k)) continue;
            out.add(
                    new AICredential() {
                        public String getName() {
                            return k.getName();
                        }

                        public String providerType() {
                            return session.providerOf(k);
                        }

                        public String baseUrl() {
                            return session.baseUrlOf(k);
                        }

                        public char[] secret() {
                            return k.getAPIKey().toCharArray();
                        }
                    });
        }
        return out;
    }
}
