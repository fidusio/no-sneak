package io.xlogistx.nosneak.v2.analysis;

import org.bouncycastle.tls.NamedGroup;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Pins the candidate list {@code enumerate-groups} offers and how it names and classifies them. */
public class GroupProbeCallbackTest {

    @Test
    public void hybridsAreOfferedFirstAndEveryCandidateHasAName() {
        int[] groups = GroupProbeCallback.CANDIDATE_GROUPS;
        assertTrue(groups.length >= 8, "expected hybrids, curves and FFDHE");
        assertTrue(GroupProbeCallback.isPqcHybrid(groups[0]), "first candidate must be a PQC hybrid");
        boolean seenClassical = false;
        for (int g : groups) {
            String name = GroupProbeCallback.groupName(g);
            assertFalse(name == null || name.isEmpty() || name.startsWith("0x"), "unnamed group " + g);
            if (!GroupProbeCallback.isPqcHybrid(g)) {
                seenClassical = true;
            } else {
                assertFalse(seenClassical, "a hybrid appears after a classical group: order must be PQC first");
            }
        }
    }

    @Test
    public void candidatesAreDistinct() {
        Set<Integer> seen = new HashSet<>();
        for (int g : GroupProbeCallback.CANDIDATE_GROUPS) {
            assertTrue(seen.add(g), "duplicate candidate " + GroupProbeCallback.groupName(g));
        }
    }

    @Test
    public void pqcClassificationFollowsMlKem() {
        assertTrue(GroupProbeCallback.isPqcHybrid(NamedGroup.X25519MLKEM768));
        assertTrue(GroupProbeCallback.isPqcHybrid(NamedGroup.SecP256r1MLKEM768));
        assertFalse(GroupProbeCallback.isPqcHybrid(NamedGroup.x25519));
        assertFalse(GroupProbeCallback.isPqcHybrid(NamedGroup.secp256r1));
        assertFalse(GroupProbeCallback.isPqcHybrid(NamedGroup.ffdhe2048));
        assertEquals("X25519MLKEM768", GroupProbeCallback.groupName(NamedGroup.X25519MLKEM768));
        assertEquals("x25519", GroupProbeCallback.groupName(NamedGroup.x25519));
    }
}
