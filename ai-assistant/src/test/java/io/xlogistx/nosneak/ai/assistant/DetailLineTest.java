package io.xlogistx.nosneak.ai.assistant;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** The assistant bubble's detail line since 2026-09-23: latency, then in / out tokens, never a total. */
public class DetailLineTest {

    @Test
    public void latencyAndBothCounts() {
        assertEquals("120 ms · 57 in / 203 out tokens", AssistantUtil.detailLine(120, 57, 203));
    }

    @Test
    public void aMissingOrZeroPartIsLeftOut() {
        assertEquals("120 ms · 203 out tokens", AssistantUtil.detailLine(120, 0, 203));
        assertEquals("120 ms · 57 in tokens", AssistantUtil.detailLine(120, 57, null));
        assertEquals("57 in / 203 out tokens", AssistantUtil.detailLine(null, 57, 203));
        assertEquals("120 ms", AssistantUtil.detailLine(120, 0, 0));
    }

    @Test
    public void nothingReportedMeansNoLine() {
        assertNull(AssistantUtil.detailLine(null, null, null));
        assertNull(AssistantUtil.detailLine(0, 0, 0));
    }
}
