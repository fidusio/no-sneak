package agent;

import java.util.List;

/**
 * Supplies the list of {@link AICredential}s the UI can use. This is the seam between the engine and
 * wherever keys are stored — the host implements it (NoSneak reads the subject's AI-flagged keys).
 */
public interface AICredentialSource {

    /**
     * @return the currently available credentials (empty, never null, when none are available).
     */
    List<AICredential> credentials();
}
