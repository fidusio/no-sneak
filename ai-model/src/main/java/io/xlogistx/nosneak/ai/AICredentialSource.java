package io.xlogistx.nosneak.ai;

import org.zoxweb.shared.data.ReferenceIDDAO;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.util.SUS;

import java.util.List;


/**
 * Interface that receives api keys from a source
 */
public interface AICredentialSource {

    List<APIKey<String>> APIKeys();

    List<APIKey<String>> enabledAPIKeys();

    void setEnabled(APIKey<String> key, boolean enabled);

    /**
     * The one definition of a key's identity — the GUID an
     * {@link io.xlogistx.nosneak.ai.model.AIProviderConfig} stores to find its credential again.
     *
     * @return the key's GUID, or null for a key the store has not persisted
     */
    static String guidOf(APIKey<?> key) {
        return (key instanceof ReferenceIDDAO dao) ? dao.getGUID() : null;
    }

    /**
     * Resolves the key an {@link io.xlogistx.nosneak.ai.model.AIProviderConfig} borrows its secret
     * from. Matched on GUID rather than name because a provider's label is editable.
     *
     * @return the key, or null when the credential is gone or the guid is blank
     */
    default APIKey<String> getKey(String guid) {
        if (SUS.isEmpty(guid)) return null;
        for (APIKey<String> k : APIKeys()) {
            if (guid.equals(guidOf(k))) return k;
        }
        return null;
    }

    /**
     * Creates a new provider API key in the backing credential store and enables it for the
     * assistant. The assistant never stores the key itself — it materializes as an ordinary
     * credential owned by the source.
     *
     * @return the created key
     * @throws SecurityException when signed out, the secret is blank, or the store rejects it
     */
    APIKey<String> addAPIKey(String label, String description, String provider, String baseURL,
                             String authType, String headerName, String secret) throws SecurityException;

}
