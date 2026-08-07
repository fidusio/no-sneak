package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.nosneak.ai.AIException;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.assistant.AIAPIProvider;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public final class PanelSupport {

    private static final DateTimeFormatter ROW_TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    private static final String[] NON_CHAT_MODEL_MARKERS = {
            "whisper", "tts", "embedding", "moderation", "dall-e", "davinci", "babbage",
            "audio", "realtime", "image", "transcribe"};

    private PanelSupport() {
    }

    /**
     * Providers are carried in the combo by id, not label — two providers can share a name, and a
     * label can be edited after a chat is already bound to it.
     */
    public static void fillProviders(AssistantContext ctx, JComboBox<String> box) {
        box.removeAllItems();
        for (AIProvider p : ctx.getProviders().getCacheMap().values()) box.addItem(p.getID());
    }

    public static ListCellRenderer<Object> providerRenderer(AssistantContext ctx) {
        return new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean selected, boolean focused) {
                AIProvider p = (value instanceof String id) ? ctx.lookupProvider(id) : null;
                return super.getListCellRendererComponent(list,
                        p != null ? p.getName() : value, index, selected, focused);
            }
        };
    }

    /**
     * Selects the entry a chat is bound to, resolving a legacy provider name to its id.
     */
    public static void selectProvider(AssistantContext ctx, JComboBox<String> box, String ref) {
        AIProvider p = ctx.lookupProvider(ref);
        box.setSelectedItem(p != null ? p.getID() : ref);
    }

    private static boolean isChatModel(String modelID) {
        if (modelID == null) return false;
        String m = modelID.toLowerCase();
        for (String marker : NON_CHAT_MODEL_MARKERS) {
            if (m.contains(marker)) return false;
        }
        return true;
    }

    public static void fillModels(AssistantContext ctx, JComboBox<String> box, String providerRef) {
        box.removeAllItems();
        AIProvider p = ctx.lookupProvider(providerRef);
        if (p == null) return;
        try {
            String[] models = p.getModelCatalog().models();
            // @TODO match models with TokenMatcher instead of the marker list
            if (models != null) for (String m : models) {
                if (isChatModel(m)) box.addItem(m);
            }
        } catch (AIException _) {
        }
    }

    /**
     * Repopulates the model combo when the provider changes, preselecting that provider's default.
     */
    public static void bindProviderModels(AssistantContext ctx, JComboBox<String> providerBox,
                                          JComboBox<String> modelBox) {
        providerBox.setEditable(false);
        providerBox.setRenderer(providerRenderer(ctx));
        providerBox.addActionListener(_ -> {
            String ref = (String) providerBox.getSelectedItem();
            fillModels(ctx, modelBox, ref);
            AIProvider p = ctx.lookupProvider(ref);
            if (p instanceof AIAPIProvider api) {
                String preferred = api.getConfig().getDefaultModel();
                if (preferred != null && !preferred.isBlank()) modelBox.setSelectedItem(preferred);
            }
        });
    }

    public static String deleteConfirm(String name, String noun) {
        String subject = (name == null || name.isBlank()) ? "this " + noun : "'" + name + "'";
        return "Delete " + subject + "? This permanently removes it.";
    }

    public static String timestamp(long millis) {
        if (millis <= 0) return "n/a";
        return ROW_TIMESTAMP.format(Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault()));
    }

    public static String blankTo(String value, String fallback) {
        String trimmed = SUS.trimOrNull(value);
        return (trimmed != null) ? trimmed : fallback;
    }
}