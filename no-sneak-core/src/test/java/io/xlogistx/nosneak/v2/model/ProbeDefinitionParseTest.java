package io.xlogistx.nosneak.v2.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ProbeDefinitionParseTest {

    private static final String VALID = """
            {
              "name": "my-echo",
              "service": "echo",
              "transport": "tcp",
              "ports": [7007],
              "priority": 90,
              "start": "hello",
              "states": {
                "hello":  { "action": "connect", "on": { "connected": "finish", "error": "stop" } },
                "finish": { "action": "done" },
                "stop":   { "action": "fail" }
              }
            }
            """;

    @Test
    public void parsesAValidDefinition() {
        ProbeDefinition def = ProbeDefinitionLoader.parse(VALID, "my-echo");
        assertEquals("my-echo", def.getName());
        assertEquals("echo", def.getService());
        assertEquals("tcp", def.getTransport());
        assertEquals(90, def.getPriority());
        assertArrayEqualsPorts(def, 7007);
    }

    private static void assertArrayEqualsPorts(ProbeDefinition def, int... expected) {
        assertEquals(expected.length, def.getPorts().length);
        for (int i = 0; i < expected.length; i++) assertEquals(expected[i], def.getPorts()[i]);
    }

    @Test
    public void malformedJsonNamesItsSource() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ProbeDefinitionLoader.parse("{ not json", "broken-probe"));
        assertTrue(e.getMessage().contains("broken-probe"), e.getMessage());
    }

    @Test
    public void structurallyInvalidDefinitionIsRejected() {
        String danglingTransition = VALID.replace("\"connected\": \"finish\"", "\"connected\": \"nowhere\"");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ProbeDefinitionLoader.parse(danglingTransition, "my-echo"));
        assertTrue(e.getMessage().contains("nowhere"), e.getMessage());
    }

    @Test
    public void unknownActionIsRejected() {
        String badAction = VALID.replace("\"action\": \"connect\"", "\"action\": \"rm-rf\"");
        assertThrows(IllegalArgumentException.class, () -> ProbeDefinitionLoader.parse(badAction, "my-echo"));
    }

    @Test
    public void definitionWithNoTerminalIsRejected() {
        String noTerminal = """
                {
                  "name": "loop",
                  "start": "a",
                  "states": {
                    "a": { "action": "connect", "on": { "connected": "b", "error": "b" } },
                    "b": { "action": "connect", "on": { "connected": "a", "error": "a" } }
                  }
                }
                """;
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ProbeDefinitionLoader.parse(noTerminal, "loop"));
        assertTrue(e.getMessage().contains("terminal"), e.getMessage());
    }

    @Test
    public void loadBundledStillGoesThroughParse() {
        assertEquals(ProbeDefinitionLoader.BUNDLED.length, ProbeDefinitionLoader.loadBundled().size());
    }
}