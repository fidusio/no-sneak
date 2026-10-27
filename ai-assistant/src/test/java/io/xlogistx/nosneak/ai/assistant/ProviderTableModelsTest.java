package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.assistant.panels.ProviderKeysTableModel;
import io.xlogistx.nosneak.ai.assistant.panels.ProvidersTableModel;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** The Providers page's two tables (2026-10-26): provider rows and the key picker's rows. */
class ProviderTableModelsTest {

    @Test
    void providerRows() {
        ProvidersTableModel.Row claude = new ProvidersTableModel.Row(null, "Claude (work)", "anthropic",
                "https://api.anthropic.com", "claude-sonnet-5-5", 12, 1_750_000_000_000L);
        ProvidersTableModel.Row fresh = new ProvidersTableModel.Row(null, "Local", "openai", "http://127.0.0.1:11434", "", 0, null);
        ProvidersTableModel m = new ProvidersTableModel();
        m.setRows(List.of(claude, fresh));

        assertEquals(ProvidersTableModel.COLS.length, m.getColumnCount());
        assertEquals("Claude (work)", m.getValueAt(0, ProvidersTableModel.COL_NAME));
        assertEquals("anthropic", m.getValueAt(0, ProvidersTableModel.COL_TYPE));
        assertEquals("https://api.anthropic.com", m.getValueAt(0, ProvidersTableModel.COL_ENDPOINT));
        assertEquals("claude-sonnet-5-5", m.getValueAt(0, ProvidersTableModel.COL_MODEL));
        assertEquals(12, m.getValueAt(0, ProvidersTableModel.COL_MODELS));
        assertEquals(1_750_000_000_000L, m.getValueAt(0, ProvidersTableModel.COL_SYNCED));
        assertEquals(Integer.class, m.getColumnClass(ProvidersTableModel.COL_MODELS));
        assertEquals(Long.class, m.getColumnClass(ProvidersTableModel.COL_SYNCED), "the sync stamp sorts as a number");

        assertEquals(0, m.getValueAt(1, ProvidersTableModel.COL_MODELS), "never synced: no models");
        assertNull(m.getValueAt(1, ProvidersTableModel.COL_SYNCED), "never synced: no stamp");
        assertEquals(-1, m.indexOf("x"), "rows without a provider never match an ID");
        assertFalse(m.isCellEditable(0, 0));
        assertSame(fresh, m.rowAt(1));
        m.setRows(null);
        assertEquals(0, m.getRowCount());
    }

    @Test
    void keyRows() {
        ProviderKeysTableModel.Row named = ProviderKeysTableModel.row(null, " Work key ", "anthropic", " https://api.anthropic.com ", 2);
        ProviderKeysTableModel.Row bare = ProviderKeysTableModel.row(null, "", null, null, 0);
        ProviderKeysTableModel m = new ProviderKeysTableModel();
        m.setRows(List.of(named, bare));

        assertEquals("Work key", m.getValueAt(0, ProviderKeysTableModel.COL_NAME));
        assertEquals("anthropic", m.getValueAt(0, ProviderKeysTableModel.COL_PROVIDER));
        assertEquals("https://api.anthropic.com", m.getValueAt(0, ProviderKeysTableModel.COL_ENDPOINT));
        assertEquals(2, m.getValueAt(0, ProviderKeysTableModel.COL_USED));
        assertEquals(ProviderKeysTableModel.UNNAMED, m.getValueAt(1, ProviderKeysTableModel.COL_NAME));
        assertEquals(ProviderKeysTableModel.CHOOSE, m.getValueAt(1, ProviderKeysTableModel.COL_PROVIDER), "a key without a known provider says so");
        assertEquals("", m.getValueAt(1, ProviderKeysTableModel.COL_ENDPOINT));
        assertEquals(Integer.class, m.getColumnClass(ProviderKeysTableModel.COL_USED));
        assertFalse(m.isCellEditable(0, 0));
    }
}
