package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.nosneak.data.ProbeContent;
import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the Probe library's rows (bundled + stored, engine order, an unparsable stored probe kept
 * with its reason), the All / Bundled / Mine + search filter, the Check message and the request
 * typed into the assistant. No Swing, no store.
 */
class ProbeLibraryModelTest {

    private static String json(String name, int priority, String description) {
        return "{\"name\":\"" + name + "\"," + (description == null ? "" : "\"description\":\"" + description + "\",")
                + "\"service\":\"redis\",\"ports\":[6379,6380],\"priority\":" + priority + ","
                + "\"start\":\"c\",\"states\":{"
                + "\"c\":{\"action\":\"connect\",\"on\":{\"connected\":\"d\"}},"
                + "\"d\":{\"action\":\"done\"}}}";
    }

    private static ProbeContent stored(String name, String content) {
        ProbeContent p = new ProbeContent();
        p.setGUID("g-" + name);
        p.setName(name);
        p.setContent(content);
        return p;
    }

    private static List<ProbeLibraryModel.Row> library() {
        List<ProbeDefinition> bundled = ProbeDefinitionLoader.loadBundled();
        Map<String, String> sources = new java.util.HashMap<>();
        for (ProbeDefinition d : bundled) sources.put(d.getName(), ProbeDefinitionLoader.bundledSource(d.getName()));
        List<ProbeContent> mine = List.of(
                stored("my-redis", json("my-redis", 60, "My Redis on 6380")),
                stored("broken", "{ not json"));
        return ProbeLibraryModel.rows(bundled, sources, mine);
    }

    @Test
    void rowsAreBundledPlusStoredInEngineOrder() {
        List<ProbeLibraryModel.Row> rows = library();
        assertEquals(ProbeDefinitionLoader.BUNDLED.length + 2, rows.size());
        assertEquals("https-scan", rows.get(0).name(), "highest priority first, as the engine runs them");
        for (int i = 1; i < rows.size(); i++) {
            assertTrue(rows.get(i - 1).priority() >= rows.get(i).priority(), "priority descending");
        }
        ProbeLibraryModel.Row ssh = rows.stream().filter(r -> r.name().equals("ssh")).findFirst().orElseThrow();
        assertFalse(ssh.stored());
        assertTrue(ssh.source().contains("\"name\": \"ssh\""), "the bundled file's own text");
        assertNotNull(ssh.description(), "every bundled probe carries a description");
        assertEquals("22, 2222", ProbeLibraryModel.ports(ssh.def()));
    }

    @Test
    void aStoredProbeThatDoesNotParseKeepsItsRowWithTheReason() {
        ProbeLibraryModel.Row broken = library().stream().filter(r -> r.name().equals("broken")).findFirst().orElseThrow();
        assertTrue(broken.stored());
        assertNull(broken.def());
        assertNotNull(broken.error());
        assertTrue(broken.error().contains("Malformed"), broken.error());
        ProbeLibraryModel model = new ProbeLibraryModel();
        model.setRows(List.of(broken));
        assertEquals("broken", model.getValueAt(0, ProbeLibraryModel.COL_NAME));
        assertEquals("?", model.getValueAt(0, ProbeLibraryModel.COL_SERVICE));
        assertEquals("mine", model.getValueAt(0, ProbeLibraryModel.COL_SOURCE));
    }

    @Test
    void theFilterIsSegmentThenSearch() {
        List<ProbeLibraryModel.Row> rows = library();
        long mine = rows.stream().filter(r -> ProbeLibraryModel.matches(r, ProbeLibraryModel.Filter.MINE, "")).count();
        long bundled = rows.stream().filter(r -> ProbeLibraryModel.matches(r, ProbeLibraryModel.Filter.BUNDLED, "")).count();
        assertEquals(2, mine);
        assertEquals(ProbeDefinitionLoader.BUNDLED.length, bundled);
        assertEquals(rows.size(), rows.stream().filter(r -> ProbeLibraryModel.matches(r, ProbeLibraryModel.Filter.ALL, " ")).count());

        List<String> byPort = rows.stream().filter(r -> ProbeLibraryModel.matches(r, ProbeLibraryModel.Filter.ALL, "2222")).map(ProbeLibraryModel.Row::name).toList();
        assertEquals(List.of("ssh"), byPort, "a port matches exactly, not as a substring");
        assertTrue(rows.stream().anyMatch(r -> r.name().equals("mysql") && ProbeLibraryModel.matches(r, ProbeLibraryModel.Filter.ALL, "MYSQL")), "name, any case");
        List<String> byService = rows.stream().filter(r -> ProbeLibraryModel.matches(r, ProbeLibraryModel.Filter.ALL, "postgresql")).map(ProbeLibraryModel.Row::name).toList();
        assertEquals(3, byService.size(), "service: the three postgres probes");
        assertTrue(rows.stream().anyMatch(r -> r.name().equals("my-redis") && ProbeLibraryModel.matches(r, ProbeLibraryModel.Filter.MINE, "6380 ")), "description text");
        assertFalse(rows.stream().anyMatch(r -> r.name().equals("my-redis") && ProbeLibraryModel.matches(r, ProbeLibraryModel.Filter.BUNDLED, "my-redis")));
    }

    @Test
    void checkMessageIsTheParsedProbeInOneLineOrTheLoadersReason() {
        assertEquals("Valid: my-redis · tcp 6379, 6380 · 2 states from c",
                ProbeLibraryModel.checkMessage(json("my-redis", 60, null)));
        assertEquals("Valid: my-redis · tcp 6379, 6380 · 2 states from c",
                ProbeLibraryModel.checkMessage("```json\n" + json("my-redis", 60, null) + "\n```"), "a fenced draft is fine");
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> ProbeLibraryModel.checkMessage("{\"name\":\"x\",\"start\":\"nowhere\",\"states\":{}}"));
        assertTrue(refused.getMessage().contains("Probe x"), "the loader's own reason: " + refused.getMessage());
    }

    @Test
    void theAssistantRequestNamesServicePortAndTheContract() {
        String prompt = ProbeLibraryModel.assistantPrompt(" MQTT ", "1883");
        assertTrue(prompt.startsWith("Write a no-sneak probe for MQTT on port 1883."), prompt);
        assertTrue(prompt.contains("section 13"), "cites the output contract");
        assertTrue(prompt.contains("```json"), "asks for the fence the save path strips");
        assertTrue(prompt.contains("description"), "asks for the optional description");
        assertTrue(ProbeLibraryModel.assistantPrompt("", "").startsWith("Write a no-sneak probe for the service."));
    }
}
