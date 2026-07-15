package agent;

import org.zoxweb.shared.api.APIConfigInfo;

/**
 * Adapts a zoxweb {@link APIConfigInfo} (plus its secret) to an {@link AICredential}, so any
 * ecosystem project that already stores API configs can feed the engine without a custom type.
 *
 * @param config the stored config — supplies the name, provider type, and base URL
 * @param secret the API secret to authenticate with
 */
public record APIConfigCredential(APIConfigInfo config, char[] secret) implements AICredential {

    public String getName() {
        return config.getName();
    }

    public String providerType() {
        return config.getAPITypeName();
    }

    public String baseUrl() {
        return config.getDefaultLocation();
    }

    public char[] secret() {
        return secret;
    }
}
