package io.xlogistx.nosneak.ai.model;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for the {@link AISkill} DAO — the companion to {@link AIChatRoundTripTest}.
 *
 * <p>Guards: the instruction text is a plain {@code String} (markdown stored verbatim), the
 * enum-typed {@code skillType} survives JSON round-trip (it follows the zoxweb enum-NVConfig
 * pattern and persists by {@code name()}), and the display names the type combo renders through
 * {@code SkillType.getName()} stay stable — the composer's popup groups by them.</p>
 */
public class AISkillRoundTripTest {

    @Test
    public void jsonRoundTripPreservesSkill() {
        AISkill original = new AISkill("summarizer", "turns a scan into a report", "# Summarize\n\n- tersely");
        original.setSkillType(AISkill.SkillType.PROMPT_SKILL);

        AISkill restored = GSONUtil.fromJSONDefault(GSONUtil.toJSONDefault(original, false), AISkill.class);

        assertEquals("summarizer", restored.getName());
        assertEquals("turns a scan into a report", restored.getDescription());
        assertEquals("# Summarize\n\n- tersely", restored.getContent(), "markdown must survive verbatim");
        assertEquals(AISkill.SkillType.PROMPT_SKILL, restored.getSkillType());
    }

    @Test
    public void nullSkillTypeSurvivesRoundTrip() {
        AISkill original = new AISkill("untyped", null, "text");

        AISkill restored = GSONUtil.fromJSONDefault(GSONUtil.toJSONDefault(original, false), AISkill.class);

        assertNull(restored.getSkillType(), "an untyped legacy skill must stay untyped, not default");
        assertEquals("text", restored.getContent());
    }

    @Test
    public void skillTypeDisplayNamesAreStable() {
        assertEquals("md skill", AISkill.SkillType.MD_SKILL.getName());
        assertEquals("prompt skill", AISkill.SkillType.PROMPT_SKILL.getName());
    }
}
