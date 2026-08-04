package io.xlogistx.nosneak.ai;

import org.zoxweb.shared.security.APIKey;

import java.util.List;


/**
 * Interface that receives api keys from a source
 */
public interface AICredentialSource {

    List<APIKey<String>> APIKeys();

    List<APIKey<String>> enabledAPIKeys();

    void setEnabled(APIKey<String> key, boolean enabled);

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
