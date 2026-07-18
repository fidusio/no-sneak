package agent.model;


import org.zoxweb.shared.data.TimeStampDAO;
import org.zoxweb.shared.util.*;

/**
 * Creates a message to send to an AI provider
 */
public class AIMessage extends TimeStampDAO {

    public enum Role {
        USER, ASSISTANT;
    }

    public enum Param implements GetNVConfig {
        ROLE(NVConfigManager.createNVConfig("role", "USER or ASSISTANT", "Role", true, true, String.class)),
        CONTENT(NVConfigManager.createNVConfig("content", "the message text", "Content", true, true, String.class));

        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_AI_MESSAGE = new NVConfigEntityPortable(
            "ai_message", null, "AIMessage", true, false, false, false,
            AIMessage.class, SharedUtil.extractNVConfigs(Param.values()), null, false,
            TimeStampDAO.NVC_TIME_STAMP_DAO
    );

    public AIMessage() {
        super(NVC_AI_MESSAGE);
    }

    public AIMessage(Role role, String content) {
        this();
        setRole(role);
        setContent(content);
        setCreationTime(System.currentTimeMillis());
    }

    public String getContent() {
        return lookupValue(Param.CONTENT);
    }

    public void setContent(String content) {

        setValue(Param.CONTENT, content);
    }

    public Role getRole() {
        String v = lookupValue(Param.ROLE);
        return v != null ? Role.valueOf(v) : null;
    }

    public void setRole(Role role) {

        setValue(Param.ROLE, role != null ? role.name() : null);
    }
}
