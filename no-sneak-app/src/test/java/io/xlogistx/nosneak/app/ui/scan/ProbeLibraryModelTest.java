package io.xlogistx.nosneak.app.ui.scan;

import io.xlogistx.scan.data.ProbeType;
import io.xlogistx.scan.model.ProbeDefinition;
import io.xlogistx.scan.model.ProbeDefinitionLoader;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the Probe library's rows (the subject's probes — the copies of the bundled set the seed
 * made and the ones written here — in engine order, an unparsable one kept with its reason),
 * the origin column, the search filter, the Check message and the request typed into the
 * assistant. No Swing, no store.
 */
class ProbeLibraryModelTest {

    private static String json(String name, int priority, String description) {
        return "{\"name\":\"" + name + "\"," + (description == null ? "" : "\"description\":\"" + description + "\",")
                + "\"service\":\"redis\",\"ports\":[6379,6380],\"priority\":" + priority + ","
                + "\"start\":\"c\",\"states\":{"
                + "\"c\":{\"action\":\"connect\",\"on\":{\"connected\":\"d\"}},"
                + "\"d\":{\"action\":\"done\"}}}";
    }

    private static ProbeType stored(String name, String content) {
        ProbeType p = new ProbeType();
        p.setGUID("g-" + name);
        p.setName(name);
        p.setDefinition(content);
        return p;
    }

    /** What a seeded subject's library holds: a copy of every bundled probe, plus two of their own. */
    private static List<ProbeType> probes() {
        List<ProbeType> mine = new ArrayList<>();
        for (ProbeDefinition d : ProbeDefinitionLoader.loadBundled()) {
            ProbeType copy = stored(d.getName(), ProbeDefinitionLoader.bundledSource(d.getName()));
            ProbeSelection.markBundledCopy(copy);
            mine.add(copy);
        }
        mine.add(stored("my-redis", json("my-redis", 60, "My Redis on 6380")));
        mine.add(stored("broken", "{ not json"));
        return mine;
    }

    private static List<ProbeLibraryModel.Row> library() {
        return ProbeLibraryModel.rows(probes());
    }

    @Test
    void rowsAreTheSubjectsProbesInEngineOrder() {
        List<ProbeLibraryModel.Row> rows = library();
        assertEquals(ProbeDefinitionLoader.BUNDLED.length + 2, rows.size());
        assertEquals("https-scan", rows.get(0).name(), "highest priority first, as the engine runs them");
        for (int i = 1; i < rows.size(); i++) {
            assertTrue(rows.get(i - 1).priority() >= rows.get(i).priority(), "priority descending");
        }
        ProbeLibraryModel.Row ssh = rows.stream().filter(r -> r.name().equals("ssh")).findFirst().orElseThrow();
        assertEquals("bundled", ssh.origin(), "a copy the seed made");
        assertTrue(ssh.source().contains("\"name\": \"ssh\""), "the copied file's own text");
        assertNotNull(ssh.description(), "every bundled probe carries a description");
        assertEquals("22, 2222", ProbeLibraryModel.ports(ssh.def()));
        ProbeLibraryModel.Row redis = rows.stream().filter(r -> r.name().equals("my-redis")).findFirst().orElseThrow();
        assertEquals("mine", redis.origin(), "written here");
        ProbeLibraryModel model = new ProbeLibraryModel();
        model.setRows(List.of(ssh, redis));
        assertEquals("bundled", model.getValueAt(0, ProbeLibraryModel.COL_SOURCE));
        assertEquals("mine", model.getValueAt(1, ProbeLibraryModel.COL_SOURCE));
    }

    @Test
    void aStoredProbeThatDoesNotParseKeepsItsRowWithTheReason() {
        ProbeLibraryModel.Row broken = library().stream().filter(r -> r.name().equals("broken")).findFirst().orElseThrow();
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
    void theFilterIsTheSearch() {
        List<ProbeLibraryModel.Row> rows = library();
        assertEquals(rows.size(), rows.stream().filter(r -> ProbeLibraryModel.matches(r, " ")).count(), "blank: everything");
        assertEquals(rows.size(), rows.stream().filter(r -> ProbeLibraryModel.matches(r, null)).count());

        List<String> byPort = rows.stream().filter(r -> ProbeLibraryModel.matches(r, "2222")).map(ProbeLibraryModel.Row::name).toList();
        assertEquals(List.of("ssh"), byPort, "a port matches exactly, not as a substring");
        assertTrue(rows.stream().anyMatch(r -> r.name().equals("mysql") && ProbeLibraryModel.matches(r, "MYSQL")), "name, any case");
        List<String> byService = rows.stream().filter(r -> ProbeLibraryModel.matches(r, "postgresql")).map(ProbeLibraryModel.Row::name).toList();
        assertEquals(3, byService.size(), "service: the three postgres probes");
        assertTrue(rows.stream().anyMatch(r -> r.name().equals("my-redis") && ProbeLibraryModel.matches(r, "6380 ")), "description text");
        assertFalse(rows.stream().anyMatch(r -> r.name().equals("ssh") && ProbeLibraryModel.matches(r, "my-redis")));
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
        IllegalArgumentException recased = assertThrows(IllegalArgumentException.class,
                () -> ProbeLibraryModel.checkMessage(json("My-Redis", 60, null)), "a name the row would re-case");
        assertTrue(recased.getMessage().endsWith("name it \"my-redis\"."), recased.getMessage());
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
