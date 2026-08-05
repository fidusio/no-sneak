package io.xlogistx.nosneak.ai.model;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

public class AIProviderConfig extends PropertyDAO {

    public enum Param implements GetNVConfig {
        KEY_GUID(NVConfigManager.createNVConfig("key_guid", "guid of the credential supplying the secret", "KeyGUID", true, true, String.class)),
        PROVIDER_TYPE(NVConfigManager.createNVConfig("provider_type", "canonical provider type: openai, anthropic, gemini, grok", "ProviderType", true, true, String.class)),
        BASE_URL(NVConfigManager.createNVConfig("base_url", "endpoint override; blank uses the provider type default", "BaseURL", false, true, String.class)),
        DEFAULT_MODEL(NVConfigManager.createNVConfig("default_model", "model preselected for a new chat on this provider", "DefaultModel", false, true, String.class)),
        ENABLED(NVConfigManager.createNVConfig("enabled", "whether the assistant registers this provider", "Enabled", false, true, Boolean.class));

        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_AI_PROVIDER_CONFIG = new NVConfigEntityPortable(
            "ai_provider_config", null, "AIProviderConfig", true, false, false, false,
            AIProviderConfig.class, SharedUtil.extractNVConfigs(Param.values()), null, false,
            PropertyDAO.NVC_PROPERTY_DAO
    );

    public AIProviderConfig() {
        super(NVC_AI_PROVIDER_CONFIG);
    }

    public AIProviderConfig(String label, String keyGUID, String providerType) {
        this();
        setName(label);
        setKeyGUID(keyGUID);
        setProviderType(providerType);
        setEnabled(true);
    }

    public String getKeyGUID() {
        return lookupValue(Param.KEY_GUID);
    }

    public void setKeyGUID(String keyGUID) {
        setValue(Param.KEY_GUID, keyGUID);
    }

    public String getProviderType() {
        return lookupValue(Param.PROVIDER_TYPE);
    }

    public void setProviderType(String providerType) {
        setValue(Param.PROVIDER_TYPE, providerType);
    }

    public String getBaseURL() {
        return lookupValue(Param.BASE_URL);
    }

    public void setBaseURL(String baseURL) {
        setValue(Param.BASE_URL, baseURL);
    }

    public String getDefaultModel() {
        return lookupValue(Param.DEFAULT_MODEL);
    }

    public void setDefaultModel(String model) {
        setValue(Param.DEFAULT_MODEL, model);
    }

    public boolean isEnabled() {
        Boolean enabled = lookupValue(Param.ENABLED);
        return enabled != null && enabled;
    }

    public void setEnabled(boolean enabled) {
        setValue(Param.ENABLED, enabled);
    }
}