package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIMessage;
import io.xlogistx.nosneak.ai.model.AIRequest;
import io.xlogistx.nosneak.ai.model.AISource;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A text attachment sent with a turn is part of the chat (2026-10-23): the chat's PDF carries its
 * content, and {@link ChatPanel#textSourcesOf} is what the "Send history" flattening feeds to
 * {@link SourceSupport#block} for every earlier turn.
 */
public class ChatHistoryContentTest {

    private static AIChat chatWithReport() {
        AIRequest req = new AIRequest();
        req.setContent("what is exposed?");
        req.addAttachment(SourceSupport.fromText("{\"host\": \"10.0.0.5\", \"open\": [443]}", "10.0.0.5"));
        AIChat chat = new AIChat("scan");
        chat.addMessage(new AIMessage(req));
        return chat;
    }

    @Test
    void pdfMarkdownCarriesTheAttachmentContent() {
        String md = ChatPanel.chatToMarkdown(null, chatWithReport(), "scan");
        assertTrue(md.contains("### You\n\nwhat is exposed?"), md);
        assertTrue(md.contains("**Attached: 10.0.0.5**"), md);
        assertTrue(md.contains("```json\n{\"host\": \"10.0.0.5\", \"open\": [443]}\n```"), md);
    }

    @Test
    void textSourcesOfSkipsImages() {
        AIRequest req = new AIRequest();
        req.addAttachment(SourceSupport.fromText("plain", "notes"));
        AISource image = new AISource(AISource.SourceType.IMAGE, "shot");
        image.setMediaType("image/png");
        req.addAttachment(image);
        List<AISource> text = ChatPanel.textSourcesOf(req);
        assertEquals(1, text.size());
        assertEquals("notes", text.get(0).getName());
    }

    @Test
    void historyBlockWrapsEachSource() {
        AIRequest req = ((AIMessage) chatWithReport().getMessages().values()[0]).getAIRequest();
        String block = SourceSupport.block(ChatPanel.textSourcesOf(req));
        assertTrue(block.startsWith("<source name=\"10.0.0.5\""), block);
        assertTrue(block.contains("\"open\": [443]"), block);
        assertTrue(block.endsWith("</source>"), block);
    }
}
