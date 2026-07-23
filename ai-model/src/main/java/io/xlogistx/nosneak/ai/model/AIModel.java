package io.xlogistx.nosneak.ai.model;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;


/**
 * Defines an AI model with name, description, and AI provider
 */
public class AIModel extends PropertyDAO {

    public enum Param implements GetNVConfig {
        PROVIDER(NVConfigManager.createNVConfig("provider", "the ai provider", "Provider", true, true, String.class));

        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_AI_MODEL = new NVConfigEntityPortable(
            "ai_model", null, "AIModel", true, false, false, false,
            AIModel.class, SharedUtil.extractNVConfigs(Param.values()), null, false,
            PropertyDAO.NVC_PROPERTY_DAO
    );

    public AIModel() {
        super(NVC_AI_MODEL);
    }

    public AIModel(String provider, String modelID) {
        this();
        setProvider(provider);
        setName(modelID);
    }

    public String getProvider() {
        return lookupValue(Param.PROVIDER);
    }

    public void setProvider(String id) {
        setValue(Param.PROVIDER, id);
    }

    public String getModelID() {
        return getName();
    }
}
