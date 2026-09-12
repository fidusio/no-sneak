package io.xlogistx.nosneak.model;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pins {@code PROBE-DEFINITION.md} — the probe-definition guide handed to an AI as a skill — to
 * the engine: every complete JSON example in it must load and validate through the real
 * loader, and the guide's allowed-action list must equal {@link ProbeDefinitionLoader#KNOWN_ACTIONS}.
 * A drift in either direction (an action added to the code but not the guide, or the guide
 * documenting something the loader rejects) fails here rather than in a generated probe.
 */
class ProbeDefinitionGuideTest {

    private static final Pattern JSON_BLOCK = Pattern.compile("```json\\s*\\n(.*?)\\n```", Pattern.DOTALL);
    private static final Pattern ACTION_RULE = Pattern.compile(
            "Every `action` is one of:(.*?)\\n\\d+\\.", Pattern.DOTALL);
    private static final Pattern BACKTICKED = Pattern.compile("`([a-z-]+)`");

    private static String guide() throws IOException {
        // Tests run with the module directory as the working directory (Maven, the IDE, the
        // CLI launcher); fall back to the repo layout in case a runner starts at the root.
        for (String candidate : new String[]{"PROBE-DEFINITION.md", "no-sneak-core/PROBE-DEFINITION.md"}) {
            Path p = Paths.get(candidate);
            if (Files.isRegularFile(p)) {
                return Files.readString(p);
            }
        }
        throw new IOException("PROBE-DEFINITION.md not found from " + Paths.get("").toAbsolutePath());
    }

    @Test
    void everyCompleteExampleInTheGuideLoadsAndValidates() throws IOException {
        Matcher m = JSON_BLOCK.matcher(guide());
        List<String> loaded = new ArrayList<>();
        while (m.find()) {
            String json = m.group(1).trim();
            if (!json.startsWith("{") || !json.contains("\"states\"")) {
                continue; // a fragment illustrating one field, not a definition
            }
            ProbeDefinition def = assertDoesNotThrow(
                    () -> ProbeDefinitionLoader.parse(json, "PROBE-DEFINITION.md example " + (loaded.size() + 1)),
                    () -> "guide example does not load:\n" + json);
            loaded.add(def.getName());
        }
        assertTrue(loaded.size() >= 8, "expected the guide's worked examples, found " + loaded);
        assertTrue(loaded.contains("https-scan"), "the deep-scan example must be present: " + loaded);
        assertTrue(loaded.contains("dns"), "the UDP example must be present: " + loaded);
    }

    @Test
    void theGuidesAllowedActionListIsExactlyWhatTheLoaderAccepts() throws IOException {
        Matcher m = ACTION_RULE.matcher(guide());
        assertTrue(m.find(), "validation rule 3 (allowed actions) not found in the guide");
        TreeSet<String> documented = new TreeSet<>();
        Matcher a = BACKTICKED.matcher(m.group(1));
        while (a.find()) {
            documented.add(a.group(1));
        }
        assertEquals(new TreeSet<>(ProbeDefinitionLoader.KNOWN_ACTIONS), documented,
                "PROBE-DEFINITION.md §8 rule 3 must list exactly the loader's KNOWN_ACTIONS");
    }

    @Test
    void everyStateFieldTheGuideDocumentsExistsOnProbeState() throws IOException {
        String g = guide();
        int start = g.indexOf("## 3. State schema");
        int end = g.indexOf("## 4. Action reference");
        assertTrue(start > 0 && end > start, "state-schema section not found");
        Matcher row = Pattern.compile("^\\| `([A-Za-z0-9]+)` \\|", Pattern.MULTILINE).matcher(g.substring(start, end));
        TreeSet<String> documented = new TreeSet<>();
        while (row.find()) {
            documented.add(row.group(1));
        }
        TreeSet<String> declared = new TreeSet<>();
        for (java.lang.reflect.Field f : ProbeState.class.getDeclaredFields()) {
            if (!java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                declared.add(f.getName());
            }
        }
        assertEquals(declared, documented, "PROBE-DEFINITION.md §3 must document exactly ProbeState's fields");
    }
}
