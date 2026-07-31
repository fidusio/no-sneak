package io.xlogistx.nosneak.ai.assistant;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import java.awt.*;

/**
 * Visual test for the chat transcript — run its {@code main} and eyeball the result.
 * Renders {@link AssistantUtil#chatBubble} over the same transcript layout, scroll pane
 * and width constraints {@code AssistantPanel.buildPromptPanel} uses, under the same
 * FlatLaf look-and-feel and custom defaults {@code Main} installs, with nothing else on
 * screen — no composer, model selector or sidebar.
 * <p>
 * The sample turns cover the cases that shape a bubble: one-word replies, wrapped
 * paragraphs, bullet and numbered lists, inline code, fenced code blocks with lines
 * wider than the bubble, and an unbroken URL. Resize the window to check wrapping at
 * different widths, and use Light/Dark to check both themes — bubble colors are read
 * from {@code UIManager} when the bubble is built, so the toolbar rebuilds the
 * transcript after switching.
 * <p>
 * Paste a provider answer into {@code RESPONSE} and run. It renders through
 * {@link AssistantMDDecoder#toMarkdown(String)} — the same wrapper-fence unwrap and repair
 * {@code AssistantCallback} applies — so a document a model wrapped in a ```md fence renders
 * here exactly as it will in the app. {@code Raw} turns the decoder off to show the untreated
 * collision.
 */
public class ChatBubbleTest {

    private static final String PROMPT = "can you send a test md file";

    private static final String RESPONSE = """
            Here’s **another** (different) longer Markdown test file:
            
            ````md
            # Another Long Test Markdown File
            
            Welcome! This file is meant to exercise common Markdown features and edge cases.
            
            ---
            
            ## A. Paragraphs & Line Breaks
            
            This is a normal paragraph.
            
            This is another paragraph with a blank line above it.
            
            If your renderer supports **soft line breaks**, the next line may wrap:
            Line one \s
            Line two (forced line break if `two spaces + newline` works)
            
            ---
            
            ## B. Emphasis & Special Inline Formatting
            
            - **Bold** text
            - *Italic* text
            - ***Bold + Italic***
            - `Inline code` example: `x = 10`
            - Escaping: \\*not italic\\*, \\_not italic\\_, \\`not code\\`
            - Strikethrough: ~~deprecated~~
            
            ---
            
            ## C. Lists
            
            ### Unordered list (with nesting)
            - Level 1
              - Level 2
                - Level 3
            - Another Level 1 item
            
            ### Ordered list
            1. First item
            2. Second item
            3. Third item
               1. Third item, sub-step 1
               2. Third item, sub-step 2
            
            ### Task list
            - [x] Create test file
            - [ ] Verify rendered output
            - [ ] Fix any issues
            
            ---
            
            ## D. Block Elements
            
            ### Blockquote (multi-line)
            > A blockquote can span multiple lines.
            >\s
            > It’s often used for notes, warnings, or quoted text.
            >
            > - Bullet points can appear inside
            
            ### Code block (with language)
            ```bash
            #!/usr/bin/env bash
            set -euo pipefail
            
            echo "Markdown test running..."
            ```
            
            ### Code block (no language)
            ```
            Plain code block line 1
            Plain code block line 2
            ```
            
            ### Another blockquote
            > Tip: Try copying this file into your Markdown renderer to check how it handles lists, tables, and code fences.
            
            ---
            
            ## E. Links & Images
            
            ### Link examples
            - Simple link: [GitHub](https://github.com)
            - Link with text: [OpenAI](https://openai.com) (learn more)
            
            ### Image example
            ![Gradient placeholder](https://via.placeholder.com/420x180.png?text=Gradient+Placeholder)
            
            ---
            
            ## F. Tables
            
            ### Basic table
            | Name | Role | Status |
            |------|------|---------|
            | Ada  | Dev  | ✅      |
            | Lin  | QA   | ⚠️      |
            | Sam  | DevOps| ❌      |
            
            ### Alignment test
            | Left | Center | Right |
            |:-----|:------:|------:|
            | a    |   b    |     c |
            | 1    |   2    |     3 |
            
            ---
            
            ## G. Horizontal Rules
            
            The content above is separated from this section by a rule.
            
            ---
            
            ## H. Misc / Edge Cases
            
            ### Headings
            #### Fourth-level heading
            Some text under a fourth-level heading.
            
            ##### Fifth-level heading
            Some more text.
            
            ### Emoji (if supported)
            - ✅ test passed
            - 🔎 checking output
            - ⚠️ renderer differences
            
            ### Endnote
            That concludes this second Markdown test file.
            ````
            
            Want it to target a specific renderer (e.g., GitHub, Notion, CommonMark, a particular Markdown-to-HTML engine)?
            
            """;

    private static boolean raw;

    public static void main(String... args) {
        FlatRobotoFont.install();
        FlatLaf.registerCustomDefaultsSource("themes");
        FlatLightLaf.setup();
        UIManager.put("defaultFont", new Font(FlatRobotoFont.FAMILY, Font.PLAIN, 13));

        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Chat bubbles");
            frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
            frame.setSize(720, 700);
            frame.setLocationRelativeTo(null);
            frame.setContentPane(buildContent(frame));
            frame.setVisible(true);
        });
    }

    private static JPanel buildContent(JFrame frame) {
        JPanel root = new JPanel(new BorderLayout());
        root.add(buildToolbar(frame), BorderLayout.NORTH);
        root.add(buildTranscript(), BorderLayout.CENTER);
        return root;
    }

    private static JComponent buildToolbar(JFrame frame) {
        JCheckBox rawToggle = new JCheckBox("Raw", raw);
        rawToggle.setToolTipText("Render the response without the decoder's fence unwrap and repair");
        rawToggle.addActionListener(_ -> {
            raw = rawToggle.isSelected();
            rebuild(frame);
        });

        JButton light = new JButton("Light");
        JButton dark = new JButton("Dark");
        light.addActionListener(_ -> applyTheme(frame, true));
        dark.addActionListener(_ -> applyTheme(frame, false));

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        bar.add(rawToggle);
        bar.add(light);
        bar.add(dark);
        return bar;
    }

    private static void rebuild(JFrame frame) {
        frame.setContentPane(buildContent(frame));
        frame.revalidate();
        frame.repaint();
    }

    private static void applyTheme(JFrame frame, boolean light) {
        if (light) FlatLightLaf.setup();
        else FlatDarkLaf.setup();
        UIManager.put("defaultFont", new Font(FlatRobotoFont.FAMILY, Font.PLAIN, 13));

        frame.setContentPane(buildContent(frame));
        SwingUtilities.updateComponentTreeUI(frame);
        frame.revalidate();
        frame.repaint();
    }

    private static JComponent buildTranscript() {
        JPanel transcript = new JPanel(new MigLayout("wrap 1, insets 14, gapy 10", "[grow]"));

        transcript.add(AssistantUtil.chatBubble(PROMPT, true, null, null), "growx, wmax 78%, alignx trailing");
        transcript.add(renderResponse(), "growx, wmax 92%, alignx leading");

        JScrollPane scroll = new JScrollPane(transcript,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        return scroll;
    }

    private static JComponent renderResponse() {
        return AssistantUtil.chatBubble(raw ? RESPONSE : AssistantMDDecoder.toMarkdown(RESPONSE), false, null, null);
    }
}