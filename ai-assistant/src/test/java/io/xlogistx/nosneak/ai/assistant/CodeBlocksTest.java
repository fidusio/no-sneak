package io.xlogistx.nosneak.ai.assistant;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The code the chat header's "Auto-copy code" box puts on the clipboard: fenced blocks only, in order. */
public class CodeBlocksTest {

    @Test
    public void fencedBlocksInOrderWithoutTheirFences() {
        String md = "Run this:\n\n```bash\nmvn clean install\n```\n\nthen edit `pom.xml`:\n\n```xml\n<a>\n  <b/>\n</a>\n```\n";
        assertEquals(List.of("mvn clean install", "<a>\n  <b/>\n</a>"), AssistantMDDecoder.codeBlocks(md));
    }

    @Test
    public void proseAndInlineCodeAreNotBlocks() {
        assertTrue(AssistantMDDecoder.codeBlocks("Use `ls -la` to list, nothing fenced.").isEmpty());
        assertTrue(AssistantMDDecoder.codeBlocks(null).isEmpty());
        assertTrue(AssistantMDDecoder.codeBlocks("").isEmpty());
    }

    @Test
    public void innerFencesStayInsideALongerOuterOne() {
        String md = "````md\n# Doc\n\n```java\nint x;\n```\n````\n";
        assertEquals(List.of("# Doc\n\n```java\nint x;\n```"), AssistantMDDecoder.codeBlocks(md));
    }

    @Test
    public void anUnclosedBlockRunsToTheEnd() {
        assertEquals(List.of("echo hi\necho there"), AssistantMDDecoder.codeBlocks("```\necho hi\necho there"));
    }

    @Test
    public void indentedFenceLosesItsIndent() {
        String md = "- step\n\n  ```sh\n  make\n  ```\n";
        assertEquals(List.of("make"), AssistantMDDecoder.codeBlocks(md));
    }
}
