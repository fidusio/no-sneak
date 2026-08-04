package io.xlogistx.nosneak.ai.assistant;

import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;
import io.xlogistx.nosneak.ai.model.AISkill;

import javax.swing.*;
import java.awt.*;

public class JPanelTest {

    static final String MARKDOWN = """
            # Skill instructions

            Edit on the left, hit **Save** to render.

            - save commits and fires the save handler
            - cancel reverts to the last committed text

            ```java
            provider.asyncSend(request, skill, callback);
            ```
            """;

    static void main(String[] args) {
        FlatRobotoFont.install();
        FlatLaf.registerCustomDefaultsSource("themes");
        FlatLightLaf.setup();
        UIManager.put("defaultFont", new Font(FlatRobotoFont.FAMILY, Font.PLAIN, 13));

        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Markdown editor");

            frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
            frame.setSize(1000, 700);
            frame.setLocationRelativeTo(null);

            MDFileViewer fileViewer = new MDFileViewer(MARKDOWN)
                    .setTitle("Skill instructions")
                    .setOnCommit(doc -> System.out.println("saved " + doc.getName() + " · " + doc.getType()
                            + " · " + doc.getMarkdown().length() + " chars"))
                    .setOnCancel(() -> System.out.println("cancelled"));

            fileViewer.withName("Scan summarizer")
                    .withDescription("Turns a scan into a short report")
                    .withTypes(AISkill.SkillType.values(), AISkill.SkillType.MD_SKILL,
                            AISkill.SkillType::getName);

            frame.setContentPane(fileViewer);
            frame.setVisible(true);
        });
    }
}