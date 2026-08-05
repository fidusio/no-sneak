package io.xlogistx.nosneak.ai;

import io.xlogistx.nosneak.ai.model.AIChat;
import io.xlogistx.nosneak.ai.model.AIProviderConfig;
import io.xlogistx.nosneak.ai.model.AISkill;

import java.util.List;

/**
 * Interface that can be used to store AIChats. To be implemented
 * as file system save, or database save
 */
public interface AIRepository {
    AIChat saveChat(AIChat chat);

    void deleteChat(AIChat chat);

    AIChat getChat(String refID);

    List<AIChat> getAllChats();


    AISkill saveSkill(AISkill skill);

    void deleteSkill(AISkill skill);

    AISkill getSkill(String refID);

    List<AISkill> getAllSkills();


    AIProviderConfig saveProviderConfig(AIProviderConfig config);

    void deleteProviderConfig(AIProviderConfig config);

    AIProviderConfig getProviderConfig(String guid);

    List<AIProviderConfig> getAllProviderConfigs();
}
