package agent.model;

/**
 * One turn in a conversation. Vendor-neutral: it holds a role and typed content (text or attachments),
 * and each provider adapts these to its own wire format.
 *
 * <p>Note: the role/content fields aren't defined yet — today this record only hosts the {@link Role}
 * and {@link Content} types it will be built from.</p>
 */
public record AIMessage() {

    /** Who sent the message. */
    public enum Role {
        USER, ASSISTANT;

        /** @return the lowercase wire form (e.g. {@code "user"}). */
        public String wire() {
            return name().toLowerCase();
        }
    }

    /**
     * A piece of message content. Vendor-neutral. Each provider adapts these to its own wire format.
     */
    public sealed interface Content permits Text, Image, Document {
    }

    /** Plain text content. */
    public record Text(String value) implements Content {
    }

    /** An image attachment (raw bytes + MIME type + name). */
    public record Image(String name, String mime, byte[] bytes) implements Content {
    }

    /** A document attachment (raw bytes + MIME type + name). */
    public record Document(String name, String mime, byte[] bytes) implements Content {
    }
}
