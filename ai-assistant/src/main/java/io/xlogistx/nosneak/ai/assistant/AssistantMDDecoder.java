package io.xlogistx.nosneak.ai.assistant;

import io.xlogistx.api.ai.AIAPI;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.util.DataDecoder;
import org.zoxweb.shared.util.GetNameValue;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVGenericMapList;
import org.zoxweb.shared.util.SUS;

import java.util.Arrays;

public class AssistantMDDecoder implements DataDecoder<NVGenericMap, String> {

    public static final AssistantMDDecoder SINGLETON = new AssistantMDDecoder();

    private static final String TRUNCATED = "\n\n> _Answer cut off: the model hit the max tokens limit._";

    private AssistantMDDecoder() {
    }

    @Override
    public String decode(NVGenericMap payload) {
        if (payload == null)
            return null;

        String markdown = AIAPI.AIMDDecoder.decode(payload);
        if (SUS.isEmpty(markdown))
            markdown = fromContentBlocks(payload);
        if (SUS.isEmpty(markdown))
            return "```json\n" + GSONUtil.toJSONDefault(payload, true) + "\n```";

        markdown = toMarkdown(markdown);
        return truncated(payload) ? closeDanglingFence(markdown) + TRUNCATED : markdown;
    }

    public static String toMarkdown(String content) {
        return neutralizeImages(repairWrapperFences(unwrapOuterFence(content)));
    }

    public static String neutralizeImages(String markdown) {
        if (markdown == null)
            return null;

        String[] lines = markdown.split("\n", -1);
        boolean rewritten = false;
        Fence open = null;
        for (int i = 0; i < lines.length; i++) {
            Fence fence = Fence.of(lines[i]);
            if (fence != null) {
                if (open == null)
                    open = fence;
                else if (fence.isBare() && fence.length >= open.length)
                    open = null;
                continue;
            }
            if (open != null)
                continue;

            String neutralized = neutralizeImageLine(lines[i]);
            if (!neutralized.equals(lines[i])) {
                lines[i] = neutralized;
                rewritten = true;
            }
        }
        return rewritten ? String.join("\n", lines) : markdown;
    }

    private static String neutralizeImageLine(String line) {
        int n = line.length();
        StringBuilder out = new StringBuilder(n);
        int i = 0;
        while (i < n) {
            char c = line.charAt(i);
            if (c == '`') {
                int run = i;
                while (run < n && line.charAt(run) == '`')
                    run++;
                int len = run - i;
                int close = closingBacktickRun(line, run, len);
                int end = (close < 0) ? run : close + len;
                out.append(line, i, end);
                i = end;
            } else if (c == '!' && i + 1 < n && line.charAt(i + 1) == '[' && notEscaped(line, i)) {
                out.append(i + 2 < n && line.charAt(i + 2) == ']' ? "[image" : "[image: ");
                i += 2;
            } else if (c == '<' && line.regionMatches(true, i, "<img", 0, 4) && isTagBoundary(line, i + 4)) {
                out.append("&lt;img");
                i += 4;
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    private static int closingBacktickRun(String line, int from, int length) {
        int i = from;
        int n = line.length();
        while (i < n) {
            if (line.charAt(i) != '`') {
                i++;
                continue;
            }
            int j = i;
            while (j < n && line.charAt(j) == '`')
                j++;
            if (j - i == length)
                return i;
            i = j;
        }
        return -1;
    }

    private static boolean notEscaped(String line, int at) {
        int backslashes = 0;
        for (int i = at - 1; i >= 0 && line.charAt(i) == '\\'; i--)
            backslashes++;
        return backslashes % 2 == 0;
    }

    private static boolean isTagBoundary(String line, int at) {
        if (at >= line.length())
            return true;
        char c = line.charAt(at);
        return c == ' ' || c == '\t' || c == '>' || c == '/';
    }

    public static String repairWrapperFences(String markdown) {
        if (markdown == null)
            return null;

        String[] lines = markdown.split("\n", -1);
        Fence[] fences = new Fence[lines.length];
        for (int i = 0; i < lines.length; i++)
            fences[i] = Fence.of(lines[i]);

        boolean rewritten = false;
        int from = 0;
        while (from < lines.length) {
            int open = wrapperOpener(fences, from);
            if (open < 0)
                break;

            int close = wrapperClose(fences, open);
            if (close < 0) {
                from = open + 1;
                continue;
            }

            int widest = 0;
            for (int i = open + 1; i < close; i++) {
                if (fences[i] != null)
                    widest = Math.max(widest, fences[i].length);
            }

            int width = Math.max(fences[open].length, widest + 1);
            if (widest > 0 && width > fences[open].length) {
                lines[open] = fences[open].indent + "`".repeat(width) + fences[open].info;
                lines[close] = fences[close].indent + "`".repeat(width);
                rewritten = true;
            }

            from = close + 1;
        }

        return rewritten ? String.join("\n", lines) : markdown;
    }

    private static int wrapperOpener(Fence[] fences, int from) {
        for (int i = from; i < fences.length; i++) {
            if (fences[i] != null && fences[i].isWrapper())
                return i;
        }
        return -1;
    }

    private static int wrapperClose(Fence[] fences, int open) {
        for (int j = fences.length - 1; j > open; j--) {
            Fence candidate = fences[j];
            if (candidate == null || !candidate.isBare() || candidate.length < fences[open].length)
                continue;
            if (nests(fences, open, j))
                return j;
        }
        return -1;
    }

    private static boolean nests(Fence[] fences, int open, int close) {
        int inner = 0;
        for (int i = open + 1; i < close; i++) {
            Fence fence = fences[i];
            if (fence == null)
                continue;

            if (fence.isWrapper())
                return false;

            if (inner == 0)
                inner = fence.length;
            else if (fence.isBare() && fence.length >= inner)
                inner = 0;
        }
        return inner == 0;
    }

    private record Fence(String indent, int length, String info) {

        static Fence of(String line) {
            int indent = 0;
            while (indent < line.length() && (line.charAt(indent) == ' ' || line.charAt(indent) == '\t'))
                indent++;

            int run = backtickRun(line.substring(indent));
            if (run < 3)
                return null;

            String info = line.substring(indent + run);
            return info.indexOf('`') < 0 ? new Fence(line.substring(0, indent), run, info) : null;
        }

        boolean isBare() {
            return info.isBlank();
        }

        boolean isWrapper() {
            String key = info.trim().toLowerCase();
            return "md".equals(key) || "markdown".equals(key);
        }
    }

    public static String unwrapOuterFence(String markdown) {
        if (markdown == null)
            return null;

        String trimmed = markdown.trim();
        int firstBreak = trimmed.indexOf('\n');
        if (firstBreak < 0)
            return markdown;

        String opening = trimmed.substring(0, firstBreak).trim();
        int fence = backtickRun(opening);
        if (fence < 3)
            return markdown;

        String info = opening.substring(fence).trim().toLowerCase();
        if (!"markdown".equals(info) && !"md".equals(info))
            return markdown;

        String body = trimmed.substring(firstBreak + 1);
        String[] lines = body.split("\n", -1);

        int close = -1;
        for (int i = lines.length - 1; i >= 0; i--) {
            String line = lines[i].trim();
            if (line.length() >= fence && backtickRun(line) == line.length()) {
                close = i;
                break;
            }
        }

        if (close >= 0) {
            boolean tailBlank = true;
            for (int i = close + 1; i < lines.length && tailBlank; i++)
                tailBlank = lines[i].isBlank();
            if (tailBlank)
                return String.join("\n", Arrays.copyOfRange(lines, 0, close));
        }

        return danglingFence(body) == null ? body : markdown;
    }

    private static int backtickRun(String line) {
        int run = 0;
        while (run < line.length() && line.charAt(run) == '`')
            run++;

        return run;
    }

    private static String fromContentBlocks(NVGenericMap payload) {
        NVGenericMap message = firstMessage(payload);
        String text = blocksToText(message != null ? message.get("content") : null);
        return SUS.isEmpty(text) ? blocksToText(payload.get("content")) : text;
    }

    private static String blocksToText(GetNameValue<?> content) {
        if (!(content instanceof NVGenericMapList blocks))
            return null;

        StringBuilder sb = new StringBuilder();
        for (NVGenericMap block : blocks.getValue()) {
            String type = block.decodedValue("type", DataDecoder.AsStringOrNull);
            if (type != null && !"text".equals(type) && !"output_text".equals(type))
                continue;

            String text = block.decodedValue("text", DataDecoder.AsStringOrNull);
            if (SUS.isEmpty(text))
                continue;

            if (!sb.isEmpty())
                sb.append("\n\n");
            sb.append(text);
        }
        return sb.toString();
    }

    static String closeDanglingFence(String markdown) {
        Fence open = danglingFence(markdown);
        return open == null ? markdown : markdown + "\n" + "`".repeat(open.length);
    }

    private static Fence danglingFence(String markdown) {
        Fence open = null;
        for (String line : markdown.split("\n", -1)) {
            Fence fence = Fence.of(line);
            if (fence == null)
                continue;

            if (open == null)
                open = fence;
            else if (fence.isBare() && fence.length >= open.length)
                open = null;
        }
        return open;
    }

    static int tokens(NVGenericMap payload) {
        if (payload == null)
            return 0;

        NVGenericMap usage = (payload.get("usage") instanceof NVGenericMap u) ? u
                : (payload.get("usageMetadata") instanceof NVGenericMap m) ? m
                : null;
        if (usage == null)
            return 0;

        Integer total = intValue(usage, "total_tokens", "totalTokenCount");
        if (total != null)
            return total;

        Integer in = intValue(usage, "prompt_tokens", "input_tokens", "promptTokenCount");
        Integer out = intValue(usage, "completion_tokens", "output_tokens", "candidatesTokenCount");
        return (in == null ? 0 : in) + (out == null ? 0 : out);
    }

    private static Integer intValue(NVGenericMap map, String... names) {
        for (String name : names) {
            GetNameValue<?> gnv = map.get(name);
            Object value = (gnv != null) ? gnv.getValue() : null;
            if (value instanceof Number number)
                return number.intValue();
            if (value instanceof String s) {
                try {
                    return Integer.parseInt(s.trim());
                } catch (NumberFormatException ignore) {
                }
            }
        }
        return null;
    }

    static boolean truncated(NVGenericMap payload) {
        NVGenericMap choice = firstChoice(payload);
        String reason = (choice != null) ? choice.decodedValue("finish_reason", DataDecoder.AsStringOrNull) : null;
        if (reason == null)
            reason = payload.decodedValue("stop_reason", DataDecoder.AsStringOrNull);
        if (reason == null) {
            NVGenericMap candidate = firstCandidate(payload);
            reason = (candidate != null) ? candidate.decodedValue("finishReason", DataDecoder.AsStringOrNull) : null;
        }

        return "length".equalsIgnoreCase(reason) || "max_tokens".equalsIgnoreCase(reason);
    }

    private static NVGenericMap firstCandidate(NVGenericMap payload) {
        return (payload.get("candidates") instanceof NVGenericMapList candidates && !candidates.getValue().isEmpty())
                ? candidates.getValue().get(0)
                : null;
    }

    private static NVGenericMap firstChoice(NVGenericMap payload) {
        return (payload.get("choices") instanceof NVGenericMapList choices && !choices.getValue().isEmpty())
                ? choices.getValue().get(0)
                : null;
    }

    private static NVGenericMap firstMessage(NVGenericMap payload) {
        NVGenericMap choice = firstChoice(payload);
        return (choice != null && choice.get("message") instanceof NVGenericMap message) ? message : null;
    }
}