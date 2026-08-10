package io.xlogistx.nosneak.ai.assistant;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ModelFilterTest {

    @Test
    public void blankFilterFallsBackToTheChatModelMarkers() {
        ModelFilter filter = new ModelFilter();

        assertTrue(filter.accepts("gpt-4o"));
        assertTrue(filter.accepts("claude-opus-4-1"));
        assertFalse(filter.accepts("whisper-1"));
        assertFalse(filter.accepts("text-embedding-3-large"));
        assertFalse(filter.accepts("gpt-4o-audio-preview"));
        assertFalse(filter.accepts(null));
        assertFalse(filter.accepts(" "));
    }

    @Test
    public void bareWordsMatchAnywhereAndAreCaseInsensitive() {
        ModelFilter filter = new ModelFilter();
        filter.setPatterns("mini");

        assertTrue(filter.accepts("gpt-4o-mini"));
        assertTrue(filter.accepts("o3-MINI"));
        assertFalse(filter.accepts("gpt-4o"));
    }

    @Test
    public void globsIncludeAndBangExcludes() {
        ModelFilter filter = new ModelFilter();
        filter.setPatterns("gpt-4*, !*preview*");

        assertTrue(filter.accepts("gpt-4o"));
        assertTrue(filter.accepts("gpt-4-turbo"));
        assertFalse(filter.accepts("gpt-4o-preview"));
        assertFalse(filter.accepts("o3"));
    }

    @Test
    public void anExcludeOnlyFilterKeepsEverythingElse() {
        ModelFilter filter = new ModelFilter();
        filter.setPatterns("!claude*");

        assertFalse(filter.accepts("claude-sonnet-4-5"));
        assertTrue(filter.accepts("gpt-4o"));
        assertTrue(filter.accepts("whisper-1"),
                "an active filter replaces the built-in markers rather than stacking on them");
    }

    @Test
    public void starMatchesEveryDiscoveredModel() {
        ModelFilter filter = new ModelFilter();
        filter.setPatterns("*");

        assertTrue(filter.accepts("whisper-1"));
        assertTrue(filter.accepts("dall-e-3"));
    }

    @Test
    public void patternsRoundTripAndClearBackToTheDefault() {
        ModelFilter filter = new ModelFilter();

        filter.setPatterns("  gpt-4*;  !*audio*  ");
        assertEquals("gpt-4*;  !*audio*", filter.getPatterns());
        assertFalse(filter.accepts("gpt-4o-audio-preview"));

        filter.setPatterns(null);
        assertEquals("", filter.getPatterns());
        assertTrue(filter.accepts("gpt-4o"));
        assertFalse(filter.accepts("whisper-1"));
    }

    @Test
    public void aLoneBangIsIgnoredRatherThanBlockingEverything() {
        ModelFilter filter = new ModelFilter();
        filter.setPatterns("!");

        assertTrue(filter.accepts("gpt-4o"));
        assertFalse(filter.accepts("whisper-1"));
    }
}