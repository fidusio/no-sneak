package io.xlogistx.nosneak.ai.assistant;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The model name the wire wants (2026-09-22). Gemini's OpenAI-compatible model listing returns
 * {@code models/<name>} while its chat calls take {@code <name>}; every other provider's ids
 * carry no prefix. {@link AIAPIProvider#MODEL_NAME} (a zoxweb {@code ReplacementFilter}) is
 * applied where the catalog is stored and where a request leaves for the wire.
 */
public class ModelNameTest {

    @Test
    public void geminiCatalogIdsLoseTheModelsPrefix() {
        assertEquals("gemini-2.0-flash", AIAPIProvider.modelName("models/gemini-2.0-flash"));
        assertEquals("gemini-2.5-pro-preview-05-06", AIAPIProvider.modelName("models/gemini-2.5-pro-preview-05-06"));
    }

    @Test
    public void bareIdsPassThroughUnchanged() {
        assertEquals("gpt-4o", AIAPIProvider.modelName("gpt-4o"));
        assertEquals("claude-opus-4-1", AIAPIProvider.modelName("claude-opus-4-1"));
        assertEquals("grok-3", AIAPIProvider.modelName("grok-3"));
    }

    @Test
    public void blankStaysBlankSoTheSendPathStillReportsAMissingModel() {
        assertNull(AIAPIProvider.modelName(null));
        assertEquals("", AIAPIProvider.modelName(""));
    }

    @Test
    public void theFilterItselfIsTheZoxwebReplacementFilter() {
        assertEquals("gemini-2.0-flash", AIAPIProvider.MODEL_NAME.validate("models/gemini-2.0-flash"));
    }
}
