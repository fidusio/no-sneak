package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIResponse;
import org.zoxweb.shared.util.SUS;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * The chat list's table (2026-10-26, the house table look; the Chat page's list since the merge): one row per
 * stored chat — title, provider, model, message count, created, updated. Pure: it holds the
 * chats it is given and resolves the provider column through the function it is built with
 * ({@code AIChat.provider} is a config GUID, which {@code AssistantContext.lookupProvider} names).
 */
public class ChatHistoryModel extends AbstractTableModel {

    public static final String[] COLS = {"Chat", "Provider", "Model", "Messages", "Created", "Updated"};
    public static final int COL_TITLE = 0, COL_PROVIDER = 1, COL_MODEL = 2, COL_MESSAGES = 3, COL_CREATED = 4, COL_UPDATED = 5;

    public static final String UNTITLED = "Untitled chat";
    public static final String NO_PROVIDER = "no provider";
    public static final String NO_MODEL = "no model";
    public static final String NO_MESSAGES = "no messages yet";

    private final Function<String, String> providerName;
    private List<AIChat> rows = List.of();

    /** @param providerName names a provider reference, or returns null when it is unknown */
    public ChatHistoryModel(Function<String, String> providerName) {
        this.providerName = providerName;
    }

    public void setRows(List<AIChat> chats) {
        rows = chats == null ? List.of() : new ArrayList<>(chats);
        fireTableDataChanged();
    }

    public AIChat rowAt(int modelRow) {
        return rows.get(modelRow);
    }

    /** The row's title: the chat's, or {@link #UNTITLED} when blank. */
    public static String title(AIChat chat) {
        String t = SUS.trimOrNull(chat.getTitle());
        return t != null ? t : UNTITLED;
    }

    /**
     * The facts line under a conversation's title (2026-10-26, the merged Chat page):
     * {@code provider · model · N messages}, with {@link #NO_PROVIDER} / {@link #NO_MODEL} /
     * {@link #NO_MESSAGES} standing in for what is missing.
     */
    public String facts(AIChat chat) {
        String model = SUS.trimOrNull(chat.getModel());
        int n = chat.getMessages() != null ? chat.getMessages().size() : 0;
        return provider(chat) + " · " + (model != null ? model : NO_MODEL) + " · "
                + (n == 0 ? NO_MESSAGES : n == 1 ? "1 message" : n + " messages");
    }

    /** The provider column: the provider's name when known, the raw reference otherwise, {@link #NO_PROVIDER} when blank. */
    public String provider(AIChat chat) {
        String ref = SUS.trimOrNull(chat.getProvider());
        if (ref == null) return NO_PROVIDER;
        String name = providerName != null ? providerName.apply(ref) : null;
        return name != null ? name : ref;
    }

    /**
     * The reply's who-answered line (2026-10-27, the conversation's provider switch):
     * {@code provider · model} from what the response recorded — the provider's name when known,
     * the raw reference otherwise; a reply saved before the provider was recorded reads as its
     * model alone; null when neither is known.
     */
    public String replyMeta(AIResponse res) {
        return replyMeta(providerName, res);
    }

    public static String replyMeta(Function<String, String> providerName, AIResponse res) {
        String ref = res == null ? null : SUS.trimOrNull(res.getProvider());
        String model = res == null ? null : SUS.trimOrNull(res.getModel());
        String name = null;
        if (ref != null) {
            String n = providerName != null ? providerName.apply(ref) : null;
            name = n != null ? n : ref;
        }
        if (name == null) return model;
        return model == null ? name : name + " · " + model;
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLS[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return switch (column) {
            case COL_MESSAGES -> Integer.class;
            case COL_CREATED, COL_UPDATED -> Long.class;
            default -> String.class;
        };
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        AIChat c = rows.get(rowIndex);
        return switch (columnIndex) {
            case COL_TITLE -> title(c);
            case COL_PROVIDER -> provider(c);
            case COL_MODEL -> SUS.trimOrNull(c.getModel()) != null ? c.getModel().trim() : "";
            case COL_MESSAGES -> c.getMessages() != null ? c.getMessages().size() : 0;
            case COL_CREATED -> c.getCreationTime();
            case COL_UPDATED -> c.getLastTimeUpdated();
            default -> "";
        };
    }
}
