package io.xlogistx.nosneak.ai.assistant;

import org.commonmark.Extension;
import org.commonmark.ext.gfm.strikethrough.StrikethroughExtension;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.ext.task.list.items.TaskListItemsExtension;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVGenericMapList;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class AssistantMDDecoderTest {

    private static final List<Extension> EXTENSIONS = Arrays.asList(
            TablesExtension.create(),
            StrikethroughExtension.create(),
            TaskListItemsExtension.create());

    private static final Parser PARSER = Parser.builder().extensions(EXTENSIONS).build();
    private static final HtmlRenderer RENDERER = HtmlRenderer.builder().extensions(EXTENSIONS).build();

    private static final String DOCUMENT = """
            # Fence Collision Test

            An intro paragraph before any block.

            ### Bare (no language)

            ```
            plain block
            ```

            ### JavaScript (fenced with language)

            ```js
            const x = 1;
            ```

            ### Python

            ```python
            x = 1
            ```

            ### Rust

            ```rust
            let x = 1;
            ```

            A closing paragraph after the last block.""";

    private static String render(String markdown) {
        return RENDERER.render(PARSER.parse(markdown == null ? "" : markdown));
    }

    private static int count(String haystack, String needle) {
        int total = 0;
        for (int at = haystack.indexOf(needle); at >= 0; at = haystack.indexOf(needle, at + needle.length()))
            total++;

        return total;
    }

    private static void assertRendersAsDocument(String unwrapped) {
        String html = render(unwrapped);
        assertTrue(html.contains("<h1>"), "document title should be a heading");
        assertTrue(html.contains("<h3>JavaScript (fenced with language)</h3>"), "swallowed heading should render");
        assertEquals(4, count(html, "<pre>"), "one pre per inner block");
        assertFalse(html.contains("<pre></pre>"), "no stray empty code box");
    }

    @Test
    public void collisionWrapperIsUnwrapped() {
        String message = "```md\n" + DOCUMENT + "\n```";

        String unwrapped = AssistantMDDecoder.unwrapOuterFence(message);
        assertEquals(DOCUMENT, unwrapped);
        assertRendersAsDocument(unwrapped);
    }

    @Test
    public void skillCompliantWrapperIsUnwrapped() {
        String message = "````md\n" + DOCUMENT + "\n````";

        String unwrapped = AssistantMDDecoder.unwrapOuterFence(message);
        assertEquals(DOCUMENT, unwrapped);
        assertRendersAsDocument(unwrapped);
    }

    @Test
    public void sourceToCopyIsNotUnwrapped() {
        String message = """
                Here is the document you asked for:

                ```md
                # Another Test

                Body text.
                ```""";

        assertEquals(message, AssistantMDDecoder.unwrapOuterFence(message));

        String html = render(message);
        assertTrue(html.contains("<pre>"), "the block stays literal source");
        assertTrue(html.contains("# Another Test"), "the block keeps its markdown verbatim");
        assertFalse(html.contains("<h1>"), "nothing inside the block becomes a heading");
    }

    @Test
    public void missingWrapperCloseUnwrapsToEnd() {
        String message = """
                ```md
                # Truncated Wrapper

                ```
                inner block
                ```

                The last paragraph of the source.""";

        String unwrapped = AssistantMDDecoder.unwrapOuterFence(message);
        assertEquals(message.substring(message.indexOf('\n') + 1), unwrapped);

        String html = render(unwrapped);
        assertEquals(1, count(html, "<pre>"), "the inner block renders once");
        assertTrue(html.contains("The last paragraph of the source."), "no content is dropped");
    }

    @Test
    public void ordinaryResponseIsNotUnwrapped() {
        String message = """
                Run this to reproduce:

                ```js
                const x = 1;
                ```

                Then check the console.""";

        assertEquals(message, AssistantMDDecoder.unwrapOuterFence(message));
        assertEquals(1, count(render(message), "<pre>"));
    }

    @Test
    public void trailingProseAfterCloseIsNotUnwrapped() {
        String message = """
                ```md
                # Doc

                Body text.
                ```
                Let me know if you want changes.""";

        assertEquals(message, AssistantMDDecoder.unwrapOuterFence(message));

        String html = render(message);
        assertEquals(1, count(html, "<pre>"), "the wrapper stays a literal block");
        assertFalse(html.contains("<h1>"), "nothing inside the block becomes a heading");
        assertTrue(html.contains("<p>Let me know if you want changes.</p>"),
                "the trailing prose stays a paragraph");
    }

    @Test
    public void fenceFirstCollisionIsRepairedNotUnwrapped() {
        String message = """
                ```md
                # Doc

                ```js
                const x = 1;
                ```
                ```
                Run it with node.""";

        assertEquals(message, AssistantMDDecoder.unwrapOuterFence(message));

        String html = render(AssistantMDDecoder.toMarkdown(message));
        assertEquals(1, count(html, "<pre>"), "the widened wrapper is one copyable block");
        assertFalse(html.contains("<h1>"), "nothing inside the block becomes a heading");
        assertTrue(html.contains("<p>Run it with node.</p>"), "the trailing prose stays a paragraph");
    }

    @Test
    public void degenerateInputsAreSafe() {
        assertNull(AssistantMDDecoder.unwrapOuterFence(null));
        assertEquals("", AssistantMDDecoder.unwrapOuterFence(""));
        assertEquals("   \n  ", AssistantMDDecoder.unwrapOuterFence("   \n  "));
        assertEquals("```md", AssistantMDDecoder.unwrapOuterFence("```md"));
        assertEquals("```\ncontent\n```", AssistantMDDecoder.unwrapOuterFence("```\ncontent\n```"));

        assertEquals("", render(null));
        assertEquals("", render(""));
    }

    @Test
    public void otherInfoStringsAreNotUnwrapped() {
        String message = """
                ```json
                {"a": 1}
                ```""";

        assertEquals(message, AssistantMDDecoder.unwrapOuterFence(message));
    }

    @Test
    public void infoStringMatchIsCaseAndSpaceInsensitive() {
        String message = "```  MarkDown  \n# Title\n\nBody.\n```";

        assertEquals("# Title\n\nBody.", AssistantMDDecoder.unwrapOuterFence(message));
    }

    private static String resource(String name) {
        try (InputStream is = AssistantMDDecoderTest.class.getResourceAsStream("/fence/" + name)) {
            assertNotNull(is, name + " missing");
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    public void promptedWrapperIsRepaired() {
        String message = resource("response-a.md");
        String repaired = AssistantMDDecoder.repairWrapperFences(message);

        assertTrue(repaired.startsWith("Sure—here's a simple test Markdown (.md) file you can copy/paste:"));
        assertTrue(repaired.contains("````md"), "wrapper widened past its contents");

        String html = render(repaired);
        assertEquals(1, count(html, "<pre>"), "the document is one copyable block");
        assertFalse(html.contains("<pre></pre>"), "no stray empty code box");

        String block = html.substring(html.indexOf("<pre>"), html.indexOf("</pre>"));
        assertTrue(block.contains("# Test Markdown File"), "document head stays inside the block");
        assertTrue(block.contains("## Link"), "document tail stays inside the same block");
        assertFalse(html.contains("<h2>"), "nothing inside the block becomes a heading");
        assertTrue(html.contains("<p>If you want, tell me what content/style you want in the test file.</p>"),
                "framing prose after the block stays a paragraph");
    }

    @Test
    public void longWrapperIsRepaired() {
        String repaired = AssistantMDDecoder.repairWrapperFences(resource("response-b.md"));

        String html = render(repaired);
        assertEquals(1, count(html, "<pre>"));

        String block = html.substring(html.indexOf("<pre>"), html.indexOf("</pre>"));
        assertTrue(block.contains("### Fenced code block (js)"));
        assertTrue(block.contains("def fibonacci"));
        assertFalse(html.contains("<h3>"), "no part of the document escapes the block");
        assertFalse(html.contains("<img"), "the image stays literal source, no remote fetch");
    }

    @Test
    public void bareInnerFenceSelectsLastCandidate() {
        String message = "Here you go:\n\n```md\n" + DOCUMENT + "\n```\n\nThat is the whole file.";

        String html = render(AssistantMDDecoder.repairWrapperFences(message));
        assertEquals(1, count(html, "<pre>"), "the language-less inner block does not close the wrapper");
        assertFalse(html.contains("<h1>"), "the document stays source, headings and all");
    }

    @Test
    public void trailingCodeBlockIsNotSwallowed() {
        String message = """
                Here is the file:

                ```md
                # Doc

                ```js
                const x = 1;
                ```
                ```

                And here is how to run it:

                ```bash
                node server.js
                ```""";

        String html = render(AssistantMDDecoder.repairWrapperFences(message));
        assertEquals(2, count(html, "<pre>"), "the wrapper closes at its own fence, not the bash block's");
        assertTrue(html.contains("<p>And here is how to run it:</p>"), "prose between the blocks survives");
    }

    @Test
    public void twoWrappersInOneMessage() {
        String wrapper = "```md\n# Doc\n\n```js\nconst x = 1;\n```\n```";
        String message = "First file:\n\n" + wrapper + "\n\nSecond file:\n\n" + wrapper + "\n\nBoth are yours.";

        String html = render(AssistantMDDecoder.repairWrapperFences(message));
        assertEquals(2, count(html, "<pre>"), "each wrapper is repaired independently");
        assertEquals(3, count(html, "<p>"), "all three framing paragraphs survive");
    }

    @Test
    public void wellFormedWrapperUntouched() {
        String message = "Here:\n\n````md\n# Doc\n\n```js\nconst x = 1;\n```\n````";

        assertEquals(message, AssistantMDDecoder.repairWrapperFences(message));
    }

    @Test
    public void noNestedFencesUntouched() {
        String message = "Here:\n\n```md\n# Doc\n\nNo inner blocks at all.\n```";

        assertEquals(message, AssistantMDDecoder.repairWrapperFences(message));
    }

    @Test
    public void ordinaryCodeBlocksUntouched() {
        String message = "Run this:\n\n```js\nconst x = 1;\n```\n\nThen check the console.";

        assertEquals(message, AssistantMDDecoder.repairWrapperFences(message));
    }

    @Test
    public void unbalancedInnerFencesLeftAlone() {
        String message = """
                Here is the file:

                ```md
                # Doc

                ```js
                const x = 1;
                ```""";

        assertEquals(message, AssistantMDDecoder.repairWrapperFences(message));
    }

    @Test
    public void repairIsIdempotent() {
        for (String message : new String[]{resource("response-a.md"), resource("response-b.md")}) {
            String once = AssistantMDDecoder.repairWrapperFences(message);
            assertEquals(once, AssistantMDDecoder.repairWrapperFences(once));
        }
    }

    @Test
    public void imageBecomesLink() {
        String message = "Here is a diagram:\n\n![Example landscape](https://example.com/x.png)\n\nDone.";
        String neutralized = AssistantMDDecoder.neutralizeImages(message);

        assertTrue(neutralized.contains("[image: Example landscape](https://example.com/x.png)"));

        String html = render(neutralized);
        assertFalse(html.contains("<img"), "no image element, no automatic fetch");
        assertTrue(html.contains("<a href=\"https://example.com/x.png\">"), "the url stays reachable by choice");
    }

    @Test
    public void referenceAndEmptyAltImagesBecomeLinks() {
        String message = "![alt][ref]\n\n![](https://example.com/y.png)\n\n[ref]: https://example.com/x.png";
        String html = render(AssistantMDDecoder.neutralizeImages(message));

        assertFalse(html.contains("<img"));
        assertTrue(html.contains("<a href=\"https://example.com/x.png\">"));
        assertTrue(html.contains("<a href=\"https://example.com/y.png\">image</a>"));
    }

    @Test
    public void rawImgTagNeutralized() {
        String message = "look:\n\n<img src=\"https://example.com/x.png\">";
        assertTrue(render(message).contains("<img"), "raw html passes through the renderer untouched");

        String html = render(AssistantMDDecoder.neutralizeImages(message));
        assertFalse(html.contains("<img"), "the escaped tag renders as text, not an element");
    }

    @Test
    public void imagesInCodeStayLiteral() {
        String fenced = "Copy this:\n\n```md\n![alt](https://example.com/x.png)\n```";
        assertEquals(fenced, AssistantMDDecoder.neutralizeImages(fenced));

        String inline = "The syntax is `![alt](url)` in markdown.";
        assertEquals(inline, AssistantMDDecoder.neutralizeImages(inline));
    }

    @Test
    public void neutralizeImagesDegenerateInputs() {
        assertNull(AssistantMDDecoder.neutralizeImages(null));
        assertEquals("", AssistantMDDecoder.neutralizeImages(""));
        assertEquals("no images here", AssistantMDDecoder.neutralizeImages("no images here"));
        assertEquals("dangling [image: ", AssistantMDDecoder.neutralizeImages("dangling !["));

        String once = AssistantMDDecoder.neutralizeImages("![a](https://example.com/x.png)");
        assertEquals(once, AssistantMDDecoder.neutralizeImages(once));
    }

    private static NVGenericMap payloadWithList(String listName, NVGenericMap element) {
        NVGenericMapList list = new NVGenericMapList(listName);
        list.add(element);
        NVGenericMap payload = new NVGenericMap();
        payload.add(list);
        return payload;
    }

    private static NVGenericMap parse(String json) {
        return GSONUtil.fromJSONDefault(json, NVGenericMap.class);
    }

    @Test
    public void tokensExtractedPerProvider() {
        String openAI = """
                {"id": "chatcmpl-1", "object": "chat.completion",
                 "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
                 "usage": {"prompt_tokens": 12, "completion_tokens": 30, "total_tokens": 42}}""";
        assertEquals(42, AssistantMDDecoder.tokens(parse(openAI)));

        String anthropic = """
                {"id": "msg_1", "role": "assistant",
                 "content": [{"type": "text", "text": "hi"}],
                 "stop_reason": "end_turn",
                 "usage": {"input_tokens": 10, "output_tokens": 20}}""";
        assertEquals(30, AssistantMDDecoder.tokens(parse(anthropic)));

        String gemini = """
                {"candidates": [{"finishReason": "STOP", "index": 0}],
                 "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 50, "totalTokenCount": 55}}""";
        assertEquals(55, AssistantMDDecoder.tokens(parse(gemini)));

        assertEquals(0, AssistantMDDecoder.tokens(new NVGenericMap()));
        assertEquals(0, AssistantMDDecoder.tokens(null));
    }

    @Test
    public void truncationDetectedPerProvider() {
        assertTrue(AssistantMDDecoder.truncated(
                payloadWithList("choices", new NVGenericMap().build("finish_reason", "length"))));
        assertTrue(AssistantMDDecoder.truncated(
                new NVGenericMap().build("stop_reason", "max_tokens")));
        assertTrue(AssistantMDDecoder.truncated(
                payloadWithList("candidates", new NVGenericMap().build("finishReason", "MAX_TOKENS"))));

        assertFalse(AssistantMDDecoder.truncated(
                payloadWithList("choices", new NVGenericMap().build("finish_reason", "stop"))));
        assertFalse(AssistantMDDecoder.truncated(
                new NVGenericMap().build("stop_reason", "end_turn")));
        assertFalse(AssistantMDDecoder.truncated(
                payloadWithList("candidates", new NVGenericMap().build("finishReason", "STOP"))));
        assertFalse(AssistantMDDecoder.truncated(new NVGenericMap()));
    }

    @Test
    public void truncationNoteClosesDanglingFence() {
        String cutMidBlock = "Here is the script:\n\n```js\nconst x = 1;";
        assertEquals(cutMidBlock + "\n```", AssistantMDDecoder.closeDanglingFence(cutMidBlock));

        String cutMidWideBlock = "````md\n# Doc\n\n```js\nconst x = 1;\n```";
        assertEquals(cutMidWideBlock + "\n````", AssistantMDDecoder.closeDanglingFence(cutMidWideBlock));

        String balanced = "Here:\n\n```js\nconst x = 1;\n```\n\nDone.";
        assertEquals(balanced, AssistantMDDecoder.closeDanglingFence(balanced));

        assertEquals("just prose", AssistantMDDecoder.closeDanglingFence("just prose"));
        assertEquals("", AssistantMDDecoder.closeDanglingFence(""));
    }

    @Test
    public void repairHandlesDegenerateInputs() {
        assertNull(AssistantMDDecoder.repairWrapperFences(null));
        assertEquals("", AssistantMDDecoder.repairWrapperFences(""));
        assertEquals("   \n  ", AssistantMDDecoder.repairWrapperFences("   \n  "));
        assertEquals("```md", AssistantMDDecoder.repairWrapperFences("```md"));
        assertEquals("prose\n\n```md", AssistantMDDecoder.repairWrapperFences("prose\n\n```md"));
        assertEquals("```", AssistantMDDecoder.repairWrapperFences("```"));
    }
}