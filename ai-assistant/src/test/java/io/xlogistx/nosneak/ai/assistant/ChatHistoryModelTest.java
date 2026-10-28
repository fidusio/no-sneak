package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.assistant.panels.ChatHistoryModel;
import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIMessage;
import io.xlogistx.nosneak.ai.model.AIRequest;
import io.xlogistx.nosneak.ai.model.AIResponse;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** The chat list's rows (2026-10-26): titles, the resolved provider, counts, stamps and the facts line. */
class ChatHistoryModelTest {

    private static AIChat chat(String title, String provider, String model) {
        AIChat c = new AIChat(title);
        c.setProvider(provider);
        c.setModel(model);
        return c;
    }

    @Test
    void columnsAndValues() {
        Map<String, String> names = Map.of("cfg-1", "Claude (work)");
        ChatHistoryModel m = new ChatHistoryModel(names::get);
        m.setRows(List.of(chat("Office segment", "cfg-1", "claude-sonnet-5-5"), chat("  ", "cfg-gone", null)));

        assertEquals(ChatHistoryModel.COLS.length, m.getColumnCount());
        assertEquals(2, m.getRowCount());
        assertEquals("Office segment", m.getValueAt(0, ChatHistoryModel.COL_TITLE));
        assertEquals("Claude (work)", m.getValueAt(0, ChatHistoryModel.COL_PROVIDER), "a known config shows its provider's name");
        assertEquals("claude-sonnet-5-5", m.getValueAt(0, ChatHistoryModel.COL_MODEL));
        assertEquals(0, m.getValueAt(0, ChatHistoryModel.COL_MESSAGES));

        assertEquals(ChatHistoryModel.UNTITLED, m.getValueAt(1, ChatHistoryModel.COL_TITLE), "a blank title reads Untitled chat");
        assertEquals("cfg-gone", m.getValueAt(1, ChatHistoryModel.COL_PROVIDER), "an unknown reference shows as itself");
        assertEquals("", m.getValueAt(1, ChatHistoryModel.COL_MODEL));
        assertEquals(Long.class, m.getColumnClass(ChatHistoryModel.COL_UPDATED), "timestamps sort as numbers");
        assertEquals(Integer.class, m.getColumnClass(ChatHistoryModel.COL_MESSAGES));
        assertFalse(m.isCellEditable(0, 0));
    }

    @Test
    void factsLine() {
        Map<String, String> names = Map.of("cfg-1", "Claude (work)");
        ChatHistoryModel m = new ChatHistoryModel(names::get);
        AIChat c = chat("Office segment", "cfg-1", "claude-sonnet-5-5");
        assertEquals("Claude (work) · claude-sonnet-5-5 · no messages yet", m.facts(c));
        c.addMessage(new AIMessage(new AIRequest("claude-sonnet-5-5", "hi", 10)));
        assertEquals("Claude (work) · claude-sonnet-5-5 · 1 message", m.facts(c));
        c.addMessage(new AIMessage(new AIRequest("claude-sonnet-5-5", "again", 10)));
        assertEquals("Claude (work) · claude-sonnet-5-5 · 2 messages", m.facts(c));
        assertEquals("no provider · no model · no messages yet", m.facts(chat("x", null, " ")));
    }

    @Test
    void replyMeta() {
        Map<String, String> names = Map.of("cfg-1", "Claude (work)");
        ChatHistoryModel m = new ChatHistoryModel(names::get);
        AIResponse r = new AIResponse();
        assertNull(m.replyMeta(r), "nothing recorded, no line");
        r.setModel("claude-sonnet-5-5");
        assertEquals("claude-sonnet-5-5", m.replyMeta(r), "a reply saved before the provider was recorded reads as its model");
        r.setProvider("cfg-1");
        assertEquals("Claude (work) · claude-sonnet-5-5", m.replyMeta(r));
        r.setProvider("cfg-gone");
        assertEquals("cfg-gone · claude-sonnet-5-5", m.replyMeta(r), "an unknown reference shows as itself");
        r.setModel(null);
        assertEquals("cfg-gone", m.replyMeta(r));
        assertNull(m.replyMeta(null));
    }

    @Test
    void noProviderAndEmptyRows() {
        ChatHistoryModel m = new ChatHistoryModel(_ -> null);
        m.setRows(List.of(chat("x", null, "m")));
        assertEquals(ChatHistoryModel.NO_PROVIDER, m.getValueAt(0, ChatHistoryModel.COL_PROVIDER));
        m.setRows(null);
        assertEquals(0, m.getRowCount());
    }
}
