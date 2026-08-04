package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.nosneak.ai.AICredentialSource;
import io.xlogistx.nosneak.ai.AIRepository;
import io.xlogistx.nosneak.ai.model.AIChat;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;
import io.xlogistx.nosneak.ai.model.AISkill;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.security.SubjectAPIKey;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

class AssistantPanelTest {

    private static class credentials implements AICredentialSource {

        private final List<APIKey<String>> keys = new ArrayList<>();
        private final Set<String> enabled = new HashSet<>();

        credentials() {
            keys.add(newKey("openai-key", "openai"));
            keys.add(newKey("claude-key", "anthropic"));
        }

        private static APIKey<String> newKey(String secret, String provider) {
            SubjectAPIKey key = new SubjectAPIKey();
            key.setName(secret);
            key.setAPIKey(secret);
            key.getProperties().build("provider", provider);
            return key;
        }

        @Override
        public List<APIKey<String>> APIKeys() {
            return new ArrayList<>(keys);
        }

        @Override
        public List<APIKey<String>> enabledAPIKeys() {
            List<APIKey<String>> out = new ArrayList<>();
            for (APIKey<String> k : keys) if (enabled.contains(k.getAPIKey())) out.add(k);
            return out;
        }

        @Override
        public void setEnabled(APIKey<String> key, boolean on) {
            if (on) enabled.add(key.getAPIKey());
            else enabled.remove(key.getAPIKey());
        }

        @Override
        public APIKey<String> addAPIKey(String label, String description, String provider, String baseURL,
                                        String authType, String headerName, String secret) {
            SubjectAPIKey key = new SubjectAPIKey();
            key.setName(label);
            key.setAPIKey(secret);
            key.getProperties().build("provider", provider);
            keys.add(key);
            enabled.add(secret);
            return key;
        }
    }

    private static class chats implements AIRepository {

        @Override
        public AIChat getChat(String refID) {
            return null;
        }

        @Override
        public List<AIChat> getAllChats() {
            return List.of();
        }

        @Override
        public AISkill saveSkill(AISkill skill) {
            return null;
        }

        @Override
        public void deleteSkill(AISkill skill) {

        }

        @Override
        public AISkill getSkill(String refID) {
            return null;
        }

        @Override
        public List<AISkill> getAllSkills() {
            return List.of();
        }

        @Override
        public AIChat saveChat(AIChat chat) {
            return null;
        }

        @Override
        public void deleteChat(AIChat chat) {

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
