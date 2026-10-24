package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.model.AISource;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** What the pending area and the transcript render for a text source (2026-10-22). */
public class SourceMarkdownTest {

    @Test
    void jsonReportIsFenced() {
        AISource source = SourceSupport.fromText("  {\"hosts\": [1, 2]}\n", "10.0.0.0/24");
        assertEquals("```json\n{\"hosts\": [1, 2]}\n```", ChatPanel.sourceMarkdown(source));
    }

    @Test
    void jsonArrayIsFenced() {
        AISource source = SourceSupport.fromText("[1, 2]", "list");
        assertEquals("```json\n[1, 2]\n```", ChatPanel.sourceMarkdown(source));
    }

    @Test
    void markdownPassesThrough() {
        String md = "# Notes\n\nsome *text*";
        AISource source = SourceSupport.fromText(md, "notes.md");
        assertEquals(md, ChatPanel.sourceMarkdown(source));
    }

    @Test
    void nullContentIsEmpty() {
        AISource source = new AISource(AISource.SourceType.TEXT, "empty");
        assertEquals("", ChatPanel.sourceMarkdown(source));
    }
}
