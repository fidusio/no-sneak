package gui;

import agent.AICredentialSource;
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


            frame.setContentPane(new AssistantPanel(new credentials()));
            frame.setVisible(true);
        });
    }
}