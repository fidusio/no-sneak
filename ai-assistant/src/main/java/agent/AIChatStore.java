package agent;

import agent.model.AIChat;

import java.util.List;

/**
 * Interface that can be used to store AIChats. To be implemented
 * as file system save, or database save
 */
public interface AIChatStore {
    AIChat save(AIChat chat);

    AIChat getChat(String topicID);

    List<AIChat> getAllChats();

    void delete(String topicID);
}
