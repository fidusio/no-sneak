package io.xlogistx.nosneak.ai.assistant.panels;

import io.xlogistx.api.ai.AIAPIBuilder;
import io.xlogistx.gui.*;
import io.xlogistx.nosneak.ai.AICredentialSource;
import io.xlogistx.nosneak.ai.AIModelCatalog;
import io.xlogistx.nosneak.ai.AIProvider;
import io.xlogistx.nosneak.ai.assistant.AIAPIProvider;
import io.xlogistx.nosneak.ai.assistant.AssistantContext;
import io.xlogistx.nosneak.ai.model.AIProviderConfig;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.blankTo;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.fillModels;
import static io.xlogistx.nosneak.ai.assistant.panels.PanelSupport.timestamp;

public class ProvidersPanel extends JPanel {
    private final AssistantContext ctx;

    private Runnable onProvidersChanged;

    public ProvidersPanel(AssistantContext ctx) {
        this.ctx = ctx;
        setLayout(new BorderLayout());
        add(buildProviderCardsPanel());
    }

    public void setOnProvidersChanged(Runnable onProvidersChanged) {
        this.onProvidersChanged = onProvidersChanged;
    }

    private static final String[] PROVIDER_DISPLAY = {"OpenAI", "Anthropic (Claude)", "Google (Gemini)", "Grok (xAI)"};
    private static final String[] PROVIDER_CANONICAL = {"openai", "anthropic", "gemini", "grok"};

    private final CardStack providerCards = new CardStack();
    private ListSection<AIProvider> providerList;
    private ListSection<APIKey<String>> providerAddList;

    private final JTextField providerFormLabel = PanelBuilder.textField("e.g. Claude prod");
    private final JComboBox<String> providerFormType = new JComboBox<>(PROVIDER_DISPLAY);
    private final JTextField providerFormBaseURL =
            PanelBuilder.textField("Optional — provider default when empty");
    private final JComboBox<String> providerFormModel = new JComboBox<>();
    private final JLabel providerFormModelLabel = new JLabel("Default model");
    private final JLabel providerFormKey = new JLabel();
    private final JButton providerFormSave = new JButton("Save", new IconUtil.SaveIcon(16));
    private AIProviderConfig editingConfig;
    private APIKey<String> editingKey;

    public JComponent buildProviderCardsPanel() {
        providerCards.add(buildProviderPanel(), "list");
        providerCards.add(buildAddProvider(), "add");
        providerCards.add(buildCreateProviderKey(), "create");
        providerCards.add(buildProviderForm(), "form");

        providerCards.show("list");
        return providerCards.view();
    }

    public JPanel buildProviderPanel() {
        providerList = ListSection.of(
                        ctx::getProvidersList
                )
                .title("Providers")
                .description("Keys come from your NoSneak credentials. Adding one here lets the assistant use it and discover its models.")
                .addButton(" + Add Provider", this::onAddProvider)
                .label(this::providerLabel)
                .sublabel(this::providerSublabel)
                .emptyText("No providers")
                .onEdit(p -> () -> onEditProvider(p))
                .onRemove(p -> () -> onRemoveProvider(p))
                .scrollable()
                .build();

        return providerList;
    }

    public JPanel buildAddProvider() {
        providerAddList = ListSection.of(this::availableKeys)
                .title("Available keys")
                .description("Pick a credential from your NoSneak key store, or add a brand-new key.")
                .label(this::keyLabel)
                .sublabel(this::keySublabel)
                .addButton("+ New Key", () -> providerCards.show("create"))
                .emptyText("No keys yet")
                .action(new ListSection.RowAction<>(new IconUtil.NextIcon(16), "Add",
                        k -> () -> onSelectAddKey(k)))
                .build();

        return PanelBuilder.detail("", () -> providerCards.show("list"),
                content -> content.add(providerAddList, "grow, push"));
    }

    public JPanel buildCreateProviderKey() {
        JTextField keyLabel = PanelBuilder.textField("e.g. Claude prod");
        JComboBox<String> provider = new JComboBox<>(PROVIDER_DISPLAY);
        JPasswordField secret = new JPasswordField(28);
        secret.putClientProperty("JTextField.placeholderText", "Your API key");
        JTextField baseURL = PanelBuilder.textField("Optional — provider default when empty");
        JButton create = new JButton("Add to assistant", new IconUtil.PlusIcon(16));

        create.addActionListener(_ -> {
            String name = keyLabel.getText().trim();
            String rawKey = new String(secret.getPassword()).trim();
            if (name.isEmpty() || rawKey.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Enter a label and the API key.",
                        "Missing information", JOptionPane.WARNING_MESSAGE);
                return;
            }
            String canonical = PROVIDER_CANONICAL[provider.getSelectedIndex()];
            String url = baseURL.getText().trim();

            BackgroundTask.run(this, create,
                    () -> ctx.getCredentials().addAPIKey(name, "", canonical, url, "", "", rawKey),
                    key -> {
                        keyLabel.setText("");
                        secret.setText("");
                        baseURL.setText("");
                        provider.setSelectedIndex(0);
                        showProviderForm(null, key);
                    });
        });

        return PanelBuilder.detail("New provider key", () -> providerCards.show("add"), panel -> {
            PanelBuilder.addRow(panel, "Label*", keyLabel);
            PanelBuilder.addRow(panel, "Provider*", provider);
            PanelBuilder.addRow(panel, "API Key*", PanelBuilder.passwordField(secret));
            PanelBuilder.addRow(panel, "Base URL", baseURL);
            panel.add(create, "gaptop 10");
        });
    }

    /**
     * The add/edit form for one provider. A key may back several of these, so everything the
     * assistant routes on lives here rather than on the credential.
     */
    public JPanel buildProviderForm() {
        providerFormModel.setEditable(true);
        providerFormSave.addActionListener(_ -> onSaveProviderConfig());

        return PanelBuilder.detail("Provider", () -> providerCards.show("list"), panel -> {
            PanelBuilder.addRow(panel, "Key", providerFormKey);
            PanelBuilder.addRow(panel, "Label*", providerFormLabel);
            PanelBuilder.addRow(panel, "Provider*", providerFormType);
            PanelBuilder.addRow(panel, "Base URL", providerFormBaseURL);
            // hidden on the add path: discovery has not run yet, so the combo would be empty
            panel.add(providerFormModelLabel, "hidemode 3");
            panel.add(providerFormModel, "growx, hidemode 3");
            panel.add(providerFormSave, "gaptop 10");
        });
    }

    /**
     * Opens the form on an existing config, or on a new one seeded from the key's own metadata.
     */
    private void showProviderForm(AIProviderConfig config, APIKey<String> key) {
        if (key == null) return;
        editingConfig = config;
        editingKey = key;

        String type = (config != null) ? config.getProviderType() : providerOf(key);
        String baseURL = (config != null) ? config.getBaseURL() : baseUrlOf(key);

        providerFormKey.setText(key.getName() != null ? key.getName() : "");
        providerFormLabel.setText(config != null && config.getName() != null
                ? config.getName() : (key.getName() != null ? key.getName() : ""));
        providerFormType.setSelectedIndex(providerIndex(type));
        providerFormBaseURL.setText(baseURL != null ? baseURL : "");
        providerFormSave.setText(config != null ? "Save" : "Add to assistant");

        providerFormModel.removeAllItems();
        providerFormModelLabel.setVisible(config != null);
        providerFormModel.setVisible(config != null);
        if (config != null) {
            fillModels(ctx, providerFormModel, config.getGUID(), false);
            providerFormModel.setSelectedItem(config.getDefaultModel());
        } else {
            providerFormModel.setSelectedItem("");
        }

        providerCards.show("form");
    }

    private void onSaveProviderConfig() {
        String label = providerFormLabel.getText().trim();
        if (label.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Give the provider a label.",
                    "Missing information", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (editingKey == null) return;

        AIProviderConfig config = (editingConfig != null) ? editingConfig : new AIProviderConfig();
        config.setName(label);
        config.setKeyGUID(keyIdentity(editingKey));
        config.setProviderType(PROVIDER_CANONICAL[providerFormType.getSelectedIndex()]);
        config.setBaseURL(providerFormBaseURL.getText().trim());
        Object model = providerFormModel.getSelectedItem();
        config.setDefaultModel(model != null ? model.toString().trim() : "");
        config.setEnabled(true);

        final APIKey<String> key = editingKey;
        BackgroundTask.run(this, providerFormSave,
                () -> {
                    AIProviderConfig saved = ctx.saveProviderConfig(config);
                    ctx.getCredentials().setEnabled(key, true);
                    AIAPIProvider p = AIAPIProvider.create(saved, key);
                    if (p != null) {
                        try {
                            p.getModelCatalog().refresh();
                        } catch (Exception ignore) {
                        }
                    }
                    return p;
                },
                p -> {
                    if (p != null) ctx.getProviders().put(p.getID(), p);
                    editingConfig = null;
                    editingKey = null;
                    refreshProviderViews();
                    providerCards.show("list");
                });
    }

    private void onSelectAddKey(APIKey<String> key) {
        if (keyIdentity(key) == null) {
            JOptionPane.showMessageDialog(this,
                    "This key has not been saved yet, so a provider cannot be attached to it.",
                    "Add provider", JOptionPane.WARNING_MESSAGE);
            return;
        }
        showProviderForm(null, key);
    }

    private void onEditProvider(AIProvider provider) {
        if (!(provider instanceof AIAPIProvider p) || p.getAPIKey() == null) return;
        showProviderForm(p.getConfig(), p.getAPIKey());
    }

    private void onAddProvider() {
        if (providerAddList != null) providerAddList.refresh();
        providerCards.show("add");
    }


    private void onRemoveProvider(AIProvider provider) {
        if (!(provider instanceof AIAPIProvider p)) return;
        int res = JOptionPane.showConfirmDialog(this,
                "Remove provider '" + p.getName() + "'? The key stays in your NoSneak credentials.",
                "Remove provider", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;

        AIProviderConfig config = p.getConfig();
        BackgroundTask.run(this, null,
                () -> {
                    ctx.deleteProviderConfig(config);
                    // assistant-enabled is derived now: the key stays linked only while some
                    // config still borrows it, so a stale flag can't resurrect it at next login.
                    APIKey<String> key = p.getAPIKey();
                    if (key != null && ctx.configsUsing(keyIdentity(key)) == 0)
                        ctx.getCredentials().setEnabled(key, false);
                    return null;
                },
                _ -> {
                    ctx.getProviders().unregister(p.getID());
                    refreshProviderViews();
                });
    }

    public void reloadProviders() {
        BackgroundTask.run(this, null, () -> {
            List<AIProviderConfig> configs = ctx.getAllProviderConfigs();
            if (configs.isEmpty()) configs = adoptEnabledKeys();

            Map<String, APIKey<String>> keysByGUID = new HashMap<>();
            for (APIKey<String> k : ctx.getCredentials().APIKeys()) {
                String guid = keyIdentity(k);
                if (guid != null) keysByGUID.put(guid, k);
            }

            List<AIProvider> built = new ArrayList<>();
            for (AIProviderConfig cfg : configs) {
                if (!cfg.isEnabled()) continue;
                APIKey<String> key = keysByGUID.get(cfg.getKeyGUID());
                if (key == null) continue;
                AIAPIProvider p = AIAPIProvider.create(cfg, key);
                if (p == null) continue;
                try {
                    p.getModelCatalog().refresh();
                } catch (Exception ignore) {
                }
                built.add(p);
            }
            return built;
        }, built -> {
            ctx.clearProviders();
            for (AIProvider p : built) ctx.getProviders().put(p.getID(), p);
            refreshProviderViews();
        });

    }

    /**
     * One-time upgrade: subjects who linked keys before providers became their own record have
     * assistant-enabled credentials and no configs. Give each one a config so their providers
     * survive the change. Runs only while the subject has none.
     */
    private List<AIProviderConfig> adoptEnabledKeys() {
        List<AIProviderConfig> out = new ArrayList<>();
        for (APIKey<String> key : ctx.getCredentials().enabledAPIKeys()) {
            String type = providerOf(key);
            String keyGUID = keyIdentity(key);
            if (keyGUID == null || AIAPIProvider.resolveType(type) == null) continue;
            AIProviderConfig cfg = new AIProviderConfig(key.getName(), keyGUID, type);
            cfg.setBaseURL(baseUrlOf(key));
            out.add(ctx.saveProviderConfig(cfg));
        }
        return out;
    }

    public void clearProviders() {
        ctx.clearProviders();
        refreshProviderViews();
    }

    public void refreshList() {
        if (providerList != null) providerList.refresh();
    }

    public void reset() {
        providerCards.show("list");
        editingConfig = null;
        editingKey = null;
    }

    /**
     * The add-list is not refreshed here — its supplier queries the credential store on the EDT,
     * and {@link #onAddProvider()} already refreshes it every time its card opens.
     */
    private void refreshProviderViews() {
        refreshList();
        if (onProvidersChanged != null) onProvidersChanged.run();
    }

    private static int providerIndex(String canonical) {
        AIAPIBuilder.AIAPIType type = AIAPIProvider.resolveType(canonical);
        if (type != null) {
            for (int i = 0; i < PROVIDER_CANONICAL.length; i++) {
                if (type == AIAPIProvider.resolveType(PROVIDER_CANONICAL[i])) return i;
            }
        }
        return 0;
    }

    private String providerLabel(AIProvider provider) {
        return provider.getName();
    }

    /**
     * The row's status line: what it talks to, and what discovery last returned. A key the
     * provider rejected registers anyway (discovery failures are swallowed at login), so
     * "0 models · never synced" is the only signal the subject gets that it is not usable.
     */
    private String providerSublabel(AIProvider provider) {
        if (!(provider instanceof AIAPIProvider p)) return null;

        StringBuilder sb = new StringBuilder(p.getConfig().getProviderType());
        sb.append("  ·  ").append(p.getBaseURL());

        String defaultModel = SUS.trimOrNull(p.getConfig().getDefaultModel());
        if (defaultModel != null) sb.append("  ·  default ").append(defaultModel);

        AIModelCatalog catalog = p.getModelCatalog();
        String[] models = catalog.models();
        int count = (models != null) ? models.length : 0;
        sb.append("  ·  ").append(count).append(count == 1 ? " model" : " models");

        Instant synced = catalog.lastSynced();
        sb.append("  ·  ").append(synced == null ? "never synced" : timestamp(synced.toEpochMilli()));
        return sb.toString();
    }

    private static String keyIdentity(APIKey<String> key) {
        return AICredentialSource.guidOf(key);
    }

    /**
     * Every credential the source offers. Unfiltered on purpose: one key can back several
     * providers, so an already-used key stays pickable.
     */
    private List<APIKey<String>> availableKeys() {
        return new ArrayList<>(ctx.getCredentials().APIKeys());
    }

    private String keyLabel(APIKey<String> key) {
        return blankTo(key.getName(), "Unnamed key");
    }

    private String keySublabel(APIKey<String> key) {
        String provider = providerOf(key);
        StringBuilder sb = new StringBuilder(
                AIAPIProvider.resolveType(provider) != null ? provider : "choose provider");

        String baseURL = SUS.trimOrNull(baseUrlOf(key));
        if (baseURL != null) sb.append("  ·  ").append(baseURL);

        int used = providersUsing(keyIdentity(key));
        if (used > 0)
            sb.append("  ·  used by ").append(used).append(used == 1 ? " provider" : " providers");
        return sb.toString();
    }

    /**
     * Counts off the registrar rather than the store: this renders per row on the EDT, and the
     * registered providers are exactly the configs in play.
     *
     * @return how many live providers borrow this credential
     */
    private int providersUsing(String keyGUID) {
        if (keyGUID == null) return 0;
        int count = 0;
        for (AIProvider p : ctx.getProvidersList()) {
            if (p instanceof AIAPIProvider api && keyGUID.equals(api.getConfig().getKeyGUID())) count++;
        }
        return count;
    }

    private String providerOf(APIKey<String> key) {
        return keyProperty(key, "provider");
    }

    private String baseUrlOf(APIKey<String> key) {
        return keyProperty(key, "base-url");
    }

    private String keyProperty(APIKey<String> key, String name) {
        Object v = (key != null && key.getProperties() != null) ? key.getProperties().getValue(name) : null;
        return v == null ? null : v.toString();
    }
}
