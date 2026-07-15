package agent;

import java.util.Set;

/**
 * Looks up the {@link AIProvider} for a given provider id. This is how a credential's
 * {@code providerType} string (e.g. {@code "anthropic"}) is turned into the impl that handles it.
 */
public interface AIProviderRegistry {

    /**
     * @return the provider for {@code providerType}, or null if none is registered.
     */
    AIProvider get(String providerType);

    /**
     * @return the provider ids this registry knows about.
     */
    Set<String> supported();
}
