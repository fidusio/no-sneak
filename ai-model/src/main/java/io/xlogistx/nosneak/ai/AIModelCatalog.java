package io.xlogistx.nosneak.ai;

import java.time.Instant;

/**
 * Remembers which models each credential offers, so opening the UI doesn't fire an HTTP call per key.
 * Backs the Providers page's model list, "Refresh" button, and "Last sync" line.
 */
public interface AIModelCatalog {

    /**
     * @return the cached models for this credential (may be empty if never synced).
     */
    String[] models();

    /**
     * Forces a fresh discovery call and updates the cache. @return the newly discovered models.
     */
    String[] refresh() throws AIException;   // Refresh button

    /**
     * @return when this credential's models were last synced, or null if never.
     */
    Instant lastSynced();
}
