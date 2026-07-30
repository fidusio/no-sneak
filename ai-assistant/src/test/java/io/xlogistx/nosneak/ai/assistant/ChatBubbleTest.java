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
 */
public class ChatBubbleTest {

    private record Turn(String text, boolean user) {
    }

    private static final Turn[] CONVERSATION = {
            new Turn("What TLS versions does 10.0.0.14 support?", true),

            new Turn("""
                    The host negotiated **TLS 1.3** and refused every earlier version.

                    - no downgrade to `TLSv1.0` or `TLSv1.1`
                    - `X25519MLKEM768` offered in the key share
                    - certificate chain terminates in a trusted root
                    """, false),

            new Turn("Is that post-quantum ready?", true),

            new Turn("""
                    Partly. The key exchange is hybrid, the signature is not:

                    1. Key agreement uses `X25519MLKEM768`, so the session is protected
                       against harvest-now-decrypt-later.
                    2. The certificate is signed with `ecdsa-with-SHA384`, which a
                       cryptographically relevant quantum computer would break.

                    > Rotating to an ML-DSA certificate is blocked on CA support.
                    """, false),

            new Turn("show me the scan line", true),

            new Turn("""
                    ```
                    nosneak scan --target 10.0.0.14 --port 443 --probe tls,pqc --timeout 5000 --json --out /var/log/nosneak/10.0.0.14.json
                    ```
                    """, false),

            new Turn("https://example.internal/reports/2026/07/29/tls-posture-10-0-0-14-full-detail.json", true),

            new Turn("Yes.", false),

            new Turn("""
                    One more thing worth noting: the transcript is flattened into a single
                    prompt before it goes out, so a long conversation grows the request every
                    turn. This paragraph exists to push the bubble across several lines so the
                    wrapping, the line spacing and the trailing padding are all visible at once
                    rather than having to be imagined from a one-liner.
                    """, false),
    };

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
        JButton light = new JButton("Light");
        JButton dark = new JButton("Dark");
        light.addActionListener(_ -> applyTheme(frame, true));
        dark.addActionListener(_ -> applyTheme(frame, false));

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        bar.add(light);
        bar.add(dark);
        return bar;
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

        for (Turn turn : CONVERSATION) {
            transcript.add(AssistantUtil.chatBubble(turn.text(), turn.user()),
                    turn.user()
                            ? "growx, wmax 78%, alignx trailing"
                            : "growx, wmax 92%, alignx leading");
        }

        JScrollPane scroll = new JScrollPane(transcript,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        return scroll;
    }
}