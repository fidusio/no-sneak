package io.xlogistx.nosneak.app;

import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.fonts.roboto.FlatRobotoFont;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.IntFunction;

/**
 * Visual test for the app's button icons — run its {@code main} and eyeball the
 * result. Shows every {@link IconUtil} icon the app uses on a real {@link JButton}
 * at the size the app uses (16×16) plus a larger 24×24 variant, under the same
 * FlatLaf look-and-feel {@code Main} installs.
 */
public class SVGIconButtonTest {

    private static final Map<String, IntFunction<Icon>> ICONS = new LinkedHashMap<>() {{
        put("back", IconUtil.BackIcon::new);
        put("copy", IconUtil.CopyIcon::new);
        put("visible", IconUtil.VisibleIcon::new);
        put("invisible", IconUtil.InvisibleIcon::new);
        put("edit", IconUtil.EditIcon::new);
        put("refresh", IconUtil.RefreshIcon::new);
        put("save", IconUtil.SaveIcon::new);
        put("search", IconUtil.SearchIcon::new);
        put("delete", IconUtil.DeleteIcon::new);
    }};

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

        for (Map.Entry<String, IntFunction<Icon>> en : ICONS.entrySet()) {
            IntFunction<Icon> icon = en.getValue();

            JButton small = GUIUtil.iconButton(icon.apply(16));
            small.setToolTipText(en.getKey());

            JButton large = GUIUtil.iconButton(icon.apply(24));
            large.setToolTipText(en.getKey());

            JButton disabled = GUIUtil.iconButton(icon.apply(16));
            disabled.setEnabled(false);

            grid.add(new JLabel(en.getKey()));
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
