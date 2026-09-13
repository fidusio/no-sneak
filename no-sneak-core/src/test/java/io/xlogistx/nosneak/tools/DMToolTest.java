package io.xlogistx.nosneak.tools;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Pins issue C1: {@code DMTool} carries no hard-coded datastore URL and resolves it in a fixed order. */
class DMToolTest {

    @Test
    void theParamWinsOverEnvironmentAndProperty() {
        assertEquals("mongodb://a/db", DMTool.resolveDbUrl("mongodb://a/db", "mongodb://b/db", "mongodb://c/db"));
    }

    @Test
    void theEnvironmentWinsOverThePropertyWhenTheParamIsAbsent() {
        assertEquals("mongodb://b/db", DMTool.resolveDbUrl(null, "mongodb://b/db", "mongodb://c/db"));
        assertEquals("mongodb://b/db", DMTool.resolveDbUrl("   ", " mongodb://b/db ", "mongodb://c/db"));
    }

    @Test
    void thePropertyIsTheLastResort() {
        assertEquals("mongodb://c/db", DMTool.resolveDbUrl(null, "", "mongodb://c/db"));
    }

    @Test
    void withNoSourceThereIsNoDefaultAndTheToolRefuses() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> DMTool.resolveDbUrl(null, null, null));
        assertTrue(e.getMessage().contains("db-url="), e.getMessage());
        assertTrue(e.getMessage().contains(DMTool.DB_URL_ENV), e.getMessage());
        assertTrue(e.getMessage().contains(DMTool.DB_URL_PROPERTY), e.getMessage());
    }

    @Test
    void noMongoUrlIsCompiledIntoTheTool() throws Exception {
        java.nio.file.Path src = java.nio.file.Paths.get("src/main/java/io/xlogistx/nosneak/tools/DMTool.java");
        if (!java.nio.file.Files.isRegularFile(src)) {
            src = java.nio.file.Paths.get("no-sneak-core").resolve(src);
        }
        String text = java.nio.file.Files.readString(src);
        assertFalse(text.contains("mongodb://localhost"), "a localhost Mongo URL crept back into DMTool");
        assertFalse(text.contains("replicaSet="), "a replica-set default crept back into DMTool");
    }
}
