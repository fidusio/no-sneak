package io.xlogistx.nosneak.ai.assistant;

import org.zoxweb.shared.filters.TokenMatcher;

public class ModelFilter {

    private static final String[] NON_CHAT_MODEL_MARKERS = {
            "whisper", "tts", "embedding", "moderation", "dall-e", "davinci", "babbage",
            "audio", "realtime", "image", "transcribe"};

    private final TokenMatcher include = new TokenMatcher(true);
    private final TokenMatcher exclude = new TokenMatcher(true);
    private String patterns = "";

    public String getPatterns() {
        return patterns;
    }

    public void setPatterns(String text) {
        patterns = (text == null) ? "" : text.trim();
        include.clear();
        exclude.clear();
        for (String token : patterns.split("[,;\\s]+")) {
            boolean negated = token.startsWith("!");
            String rule = negated ? token.substring(1) : token;
            if (rule.isBlank()) continue;
            if (rule.indexOf('*') < 0 && rule.indexOf('?') < 0) rule = "*" + rule + "*";
            if (negated) exclude.addPattern(rule);
            else include.addPattern(rule);
        }
    }

    public boolean accepts(String modelID) {
        if (modelID == null || modelID.isBlank()) return false;
        if (include.size() == 0 && exclude.size() == 0) return isChatModel(modelID);
        if (exclude.matches(modelID)) return false;
        return include.size() == 0 || include.matches(modelID);
    }

    public static boolean isChatModel(String modelID) {
        if (modelID == null || modelID.isBlank()) return false;
        String m = modelID.toLowerCase();
        for (String marker : NON_CHAT_MODEL_MARKERS) {
            if (m.contains(marker)) return false;
        }
        return true;
    }
}