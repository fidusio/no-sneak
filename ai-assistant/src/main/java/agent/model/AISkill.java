package agent.model;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

public class AISkill extends PropertyDAO {

    public enum Param implements GetNVConfig {
        CONTENT(NVConfigManager.createNVConfig("content", "the skill text", "Content", true, true, String.class));

        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_AI_SKILL = new NVConfigEntityPortable(
            "ai_skill", null, "AISkill", true, false, false, false,
            AISkill.class, SharedUtil.extractNVConfigs(Param.values()), null, false,
            PropertyDAO.NVC_PROPERTY_DAO
    );

    public AISkill() {
        super(NVC_AI_SKILL);
    }

    public AISkill(String name, String description, String content) {
        this();
        setName(name);
        setDescription(description);
        setContent(content);
    }

    public String getContent() {
        return lookupValue(Param.CONTENT);
    }

    public void setContent(String content) {
        setValue(Param.CONTENT, content);
    }
}
