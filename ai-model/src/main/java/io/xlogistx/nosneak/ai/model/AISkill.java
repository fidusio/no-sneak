package io.xlogistx.nosneak.ai.model;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

/**
 * A reusable instruction set. {@code content} is the instruction text as a plain string, so a
 * skill authored in markdown is stored verbatim — there is no file reference and no export.
 * <p>
 * <b>{@link SkillType} is not cosmetic</b> — it decides what the composer does when a skill is
 * checked: an {@code MD_SKILL} is <i>attached</i> (flattened into the system-prompt argument the
 * provider receives), while a {@code PROMPT_SKILL} has its text <i>inserted into the message box</i>
 * for the subject to edit before sending. A prompt skill is deliberately never also attached, or
 * the same text would go out twice.
 * <p>
 * One consequence worth knowing: prompt-skill text is persisted as ordinary message content, but
 * an attached md skill is recorded nowhere — {@link AIRequest} has no field for it, so the stored
 * transcript cannot tell you what the model was actually instructed with.
 */
public class AISkill extends PropertyDAO {

    public enum SkillType implements GetName{
        MD_SKILL("md skill"), PROMPT_SKILL("prompt skill");

        private final String name;

        SkillType(String name) {this.name = name; }

        @Override
        public String getName() {
            return name;
        }
    }

    public enum Param implements GetNVConfig {
        CONTENT(NVConfigManager.createNVConfig("content", "the skill text", "Content", true, true, String.class)),
        SKILL_TYPE(NVConfigManager.createNVConfig("skill_type", "the skill type", "SkillType", false, true, SkillType.class));

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

    public SkillType getSkillType() {
        return lookupValue(Param.SKILL_TYPE);
    }

    public void setSkillType(SkillType skillType) {
        setValue(Param.SKILL_TYPE, skillType);
    }
}
