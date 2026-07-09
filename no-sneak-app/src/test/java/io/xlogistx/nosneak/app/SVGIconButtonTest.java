package io.xlogistx.nosneak.app;

import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.extras.FlatSVGIcon;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;

import javax.swing.*;
import java.awt.*;

/**
 * Visual test for the bundled SVG button icons — run its {@code main} and eyeball the
 * result. Shows every icon from {@code src/main/resources/icons/} on a real
 * {@link JButton} at the size the app uses (16×16) plus a larger 24×24 variant,
 * under the same FlatLaf look-and-feel {@code Main} installs.
 */
public class SVGIconButtonTest {

    private static final String[] ICONS = {
            "arrow-left", "check", "copy", "eye", "eye-off",
            "pencil", "rotate", "save", "search", "trash"
    };

    public static void main(String... args) {
        FlatRobotoFont.install();
        FlatLaf.registerCustomDefaultsSource("themes");
        FlatLightLaf.setup();
        UIManager.put("defaultFont", new Font(FlatRobotoFont.FAMILY, Font.PLAIN, 13));

        SwingUtilities.invokeLater(SVGIconButtonTest::showFrame);
    }

    private static void showFrame() {
        JPanel grid = new JPanel(new GridLayout(0, 4, 8, 8));
        grid.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        grid.add(header("Icon"));
        grid.add(header("16×16 (app size)"));
        grid.add(header("24×24"));
        grid.add(header("Disabled"));

        for (String name : ICONS) {
            String resource = "icons/" + name + ".svg";

            JButton small = new JButton(new FlatSVGIcon(resource, 16, 16));
            small.setToolTipText(name);

            JButton large = new JButton(new FlatSVGIcon(resource, 24, 24));
            large.setToolTipText(name);

            JButton disabled = new JButton(new FlatSVGIcon(resource, 16, 16));
            disabled.setEnabled(false);

            grid.add(new JLabel(name + ".svg"));
            grid.add(small);
            grid.add(large);
            grid.add(disabled);
        }

        JFrame frame = new JFrame("SVG icon buttons");
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setContentPane(new JScrollPane(grid));
        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private static JLabel header(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        return label;
    }
}
