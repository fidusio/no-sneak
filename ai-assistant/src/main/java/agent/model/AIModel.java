package agent.model;

/**
 * A model a provider offers.
 *
 * @param id          the wire id used in requests
 * @param displayName the human-friendly name shown in the UI
 */
public record AIModel(String id, String displayName) {

    /** Uses the id as the display name too. */
    public AIModel(String id) {
        this(id, id);
    }
}
