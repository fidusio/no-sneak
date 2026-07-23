package gui;

import agent.AICredentialSource;
import agent.AIChatRepository;
import agent.model.AIChat;
import agent.model.AssistantContext;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.security.SubjectAPIKey;

import javax.swing.*;
import java.awt.*;
import java.util.Collections;
import java.util.List;

class AssistantPanelTest {

    private static class credentials implements AICredentialSource {

        @Override
        public List<APIKey<String>> APIKeys() {
            SubjectAPIKey key = new SubjectAPIKey();
            key.setAPIKey("Asdf");
            return Collections.singletonList(key);
        }
    }

    private static class chats implements AIChatRepository {
        @Override
        public AIChat save(AIChat chat) {
            return chat;
        }

        @Override
        public AIChat getChat(String refID) {
            return null;
        }

        @Override
        public List<AIChat> getAllChats() {
            return List.of();
        }

        @Override
        public void delete(AIChat chat) {

        }
    }

    static void main(String[] args) {
        FlatRobotoFont.install();
        FlatLaf.registerCustomDefaultsSource("themes");
        FlatLightLaf.setup();
        UIManager.put("defaultFont", new Font(FlatRobotoFont.FAMILY, Font.PLAIN, 13));

        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("AI Assistant");

            frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
            frame.setSize(800, 600);
            frame.setLocationRelativeTo(null);


            frame.setContentPane(new AssistantPanel(new AssistantContext(new credentials(), new chats())));
            frame.setVisible(true);
        });
    }
}