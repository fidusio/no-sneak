package agent;

import org.zoxweb.shared.util.GetName;

/**
 * One AI endpoint the engine can talk to. This is the only door to a provider — a name, which
 * provider it is, where to reach it, and the secret to authenticate. Hosts supply these (see
 * {@link AICredentialSource}); the engine never knows where they came from.
 */
public interface AICredential extends GetName {

    /**
     * @return the vendor id (e.g. {@code "anthropic"}); selects the {@link AIProvider} impl.
     */
    String providerType();

    /**
     * @return the endpoint base URL to send requests to.
     */
    String baseUrl();

    /**
     * @return the API secret as a {@code char[]} (never a {@code String}).
     */
    char[] secret();
}
