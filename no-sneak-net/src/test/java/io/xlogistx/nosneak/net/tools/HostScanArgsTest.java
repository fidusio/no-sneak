package io.xlogistx.nosneak.net.tools;

import io.xlogistx.nosneak.net.common.SweepOptions;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Command-line parsing, which the shell and the one-shot path share. Needs no
 * network: this is where the multi-target behaviour is pinned down.
 */
public class HostScanArgsTest {

    private static final Duration T = Duration.ofSeconds(2);

    private static HostScan.Args ping(String... argv) {
        return HostScan.Args.parse(argv, 4, T, true);
    }

    private static HostScan.Args sweep(String... argv) {
        return HostScan.Args.parse(argv, 1, Duration.ofMillis(1000), false);
    }

    @Test
    public void singleTargetTakesTheDefaults() {
        HostScan.Args a = ping("ping", "10.0.0.1");
        assertEquals(List.of("10.0.0.1"), a.targets());
        assertEquals(4, a.count());
        assertEquals(T, a.timeout());
        assertNull(a.iface());
    }

    @Test
    public void severalTargetsAreAllKept() {
        assertEquals(List.of("10.0.0.1", "10.0.0.2", "router.local"),
                     ping("ping", "10.0.0.1", "10.0.0.2", "router.local").targets());
    }

    /** 'ping 10.0.0.1 7' has always meant seven probes; multi-target must not break it. */
    @Test
    public void bareTrailingNumberIsStillTheCount() {
        HostScan.Args one = ping("ping", "10.0.0.1", "7");
        assertEquals(List.of("10.0.0.1"), one.targets());
        assertEquals(7, one.count());

        HostScan.Args many = ping("ping", "10.0.0.1", "10.0.0.2", "3");
        assertEquals(List.of("10.0.0.1", "10.0.0.2"), many.targets());
        assertEquals(3, many.count());
    }

    /** A lone digit string is a target, not a count — there is nothing left to ping otherwise. */
    @Test
    public void aLoneNumberIsATarget() {
        assertEquals(List.of("7"), ping("ping", "7").targets());
    }

    /** Sweep never strips a trailing number: a bare integer is not a CIDR, and hiding it hides the typo. */
    @Test
    public void sweepKeepsTrailingNumbers() {
        assertEquals(List.of("10.0.0.0/24", "3"), sweep("sweep", "10.0.0.0/24", "3").targets());
    }

    @Test
    public void flagsOverrideDefaults() {
        HostScan.Args a = ping("ping", "-c", "2", "-w", "500", "-i", "eth0", "10.0.0.1");
        assertEquals(2, a.count());
        assertEquals(Duration.ofMillis(500), a.timeout());
        assertEquals("eth0", a.iface());
        assertEquals(List.of("10.0.0.1"), a.targets());
    }

    @Test
    public void longFlagsToo() {
        HostScan.Args a = ping("ping", "--count", "9", "--timeout", "250", "--iface", "en0", "::1");
        assertEquals(9, a.count());
        assertEquals(Duration.ofMillis(250), a.timeout());
        assertEquals("en0", a.iface());
    }

    /** An explicit count wins; the trailing-number shorthand is off once -c is given. */
    @Test
    public void explicitCountSuppressesTheShorthand() {
        HostScan.Args a = ping("ping", "-c", "2", "10.0.0.1", "10.0.0.2", "5");
        assertEquals(2, a.count());
        assertEquals(List.of("10.0.0.1", "10.0.0.2", "5"), a.targets());
    }

    @Test
    public void unknownOptionIsRejected() {
        assertTrue(assertThrows(IllegalArgumentException.class, () -> ping("ping", "-z", "10.0.0.1"))
                           .getMessage().contains("-z"));
    }

    @Test
    public void optionWithoutAValueIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ping("ping", "10.0.0.1", "-c"));
    }

    @Test
    public void nonsenseCountsAndTimeoutsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> ping("ping", "-c", "0", "10.0.0.1"));
        assertThrows(IllegalArgumentException.class, () -> ping("ping", "-w", "0", "10.0.0.1"));
    }

    @Test
    public void emptyTargetListIsCaughtBeforeAnythingIsSent() {
        assertThrows(IllegalArgumentException.class,
                     () -> ping("ping").requireTargets("an IP address"));
    }

    /** The command's count and timeout must reach the sweep, not just the ping path. */
    @Test
    public void sweepOptionsCarryTheCommandsTuning() {
        SweepOptions o = sweep("sweep", "-c", "3", "-w", "400", "10.0.0.0/24").sweepOptions();
        assertEquals(3, o.pingCount());
        assertEquals(Duration.ofMillis(400), o.perHostTimeout());
        assertEquals(SweepOptions.defaults().maxPacketsPerSecond(), o.maxPacketsPerSecond());
        assertEquals(SweepOptions.defaults().maxHosts(), o.maxHosts());
    }

    @Test
    public void tokenizeIgnoresBlankAndRepeatedSpaces() {
        assertEquals(0, HostScan.tokenize("   ").length);
        assertEquals(3, HostScan.tokenize("  ping   10.0.0.1  10.0.0.2 ").length);
    }
}
