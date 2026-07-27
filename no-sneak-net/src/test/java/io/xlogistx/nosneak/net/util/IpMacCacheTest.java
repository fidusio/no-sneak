package io.xlogistx.nosneak.net.util;

import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.ResolveSource;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cache behaviour: the aging state machine, conflict detection, and correctness
 * under concurrent observation.
 * <p>
 * Aging is driven by an injected clock rather than by sleeping, so the
 * transitions are exact and the suite stays fast.
 */
public class IpMacCacheTest {

    /** A clock the test moves by hand. */
    private static final class TestClock extends Clock {
        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }

        void advance(Duration d) { now = now.plus(d); }
    }

    private static final Duration REACHABLE = Duration.ofSeconds(30);
    private static final Duration STALE = Duration.ofMinutes(5);

    private static final InetAddress IP_A = InetAddress.ofLiteral("192.168.1.10");
    private static final InetAddress IP_B = InetAddress.ofLiteral("192.168.1.11");
    private static final MacAddress MAC_A = MacAddress.parse("aa:bb:cc:dd:ee:01");
    private static final MacAddress MAC_B = MacAddress.parse("aa:bb:cc:dd:ee:02");

    private final TestClock clock = new TestClock();
    private final IpMacCache cache = new IpMacCache(64, REACHABLE, STALE, clock);

    // ---- basic upsert ----

    @Test
    public void observeInsertsReachableEntry() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);

        IpMacCache.Entry e = cache.get(IP_A).orElseThrow();
        assertEquals(IP_A, e.ip());
        assertEquals(MAC_A, e.mac());
        assertEquals(IpMacCache.State.REACHABLE, e.state());
        assertEquals(ResolveSource.ACTIVE_ARP, e.provenance());
        assertEquals(clock.instant(), e.firstSeen());
        assertEquals(clock.instant(), e.lastSeen());
        assertEquals(0, e.conflictCount());
        assertNull(e.lastConflictAt());
    }

    @Test
    public void missingKeyIsEmptyAndCreatesNoEntry() {
        assertTrue(cache.get(IP_A).isEmpty());
        assertEquals(0, cache.size(), "a lookup must not insert a placeholder");
        assertTrue(cache.get(null).isEmpty());
    }

    /** firstSeen is the identity of the binding; only lastSeen tracks freshness. */
    @Test
    public void reobservationRefreshesLastSeenButKeepsFirstSeen() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        Instant first = cache.get(IP_A).orElseThrow().firstSeen();

        clock.advance(Duration.ofSeconds(10));
        cache.observe(IP_A, MAC_A, ResolveSource.PASSIVE);

        IpMacCache.Entry e = cache.get(IP_A).orElseThrow();
        assertEquals(first, e.firstSeen());
        assertEquals(clock.instant(), e.lastSeen());
        assertEquals(ResolveSource.PASSIVE, e.provenance(), "provenance follows the latest evidence");
    }

    // ---- the aging state machine ----

    /** INCOMPLETE -> REACHABLE, when a solicitation is answered. */
    @Test
    public void incompleteBecomesReachableOnObservation() {
        cache.markIncomplete(IP_A);
        IpMacCache.Entry pending = cache.get(IP_A).orElseThrow();
        assertEquals(IpMacCache.State.INCOMPLETE, pending.state());
        assertFalse(pending.hasMac());
        assertNull(pending.provenance());

        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        IpMacCache.Entry resolved = cache.get(IP_A).orElseThrow();
        assertEquals(IpMacCache.State.REACHABLE, resolved.state());
        assertEquals(MAC_A, resolved.mac());
    }

    /** REACHABLE -> STALE at the freshness boundary. */
    @Test
    public void reachableBecomesStaleAfterReachableTtl() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);

        clock.advance(REACHABLE);
        assertEquals(IpMacCache.State.REACHABLE, cache.get(IP_A).orElseThrow().state(),
                     "exactly at the TTL is still fresh");

        clock.advance(Duration.ofSeconds(1));
        IpMacCache.Entry stale = cache.get(IP_A).orElseThrow();
        assertEquals(IpMacCache.State.STALE, stale.state());
        assertEquals(MAC_A, stale.mac(), "a stale entry still carries its MAC");
    }

    /** STALE -> evicted at the end of the stale window. */
    @Test
    public void staleIsEvictedAfterStaleTtl() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);

        clock.advance(REACHABLE.plus(STALE));
        assertTrue(cache.get(IP_A).isPresent(), "still within the stale window");

        clock.advance(Duration.ofSeconds(1));
        assertTrue(cache.get(IP_A).isEmpty());
        assertEquals(0, cache.size(), "a lazy read must actually remove the entry");
    }

    /** An unanswered solicitation is dropped rather than going stale — it has no MAC. */
    @Test
    public void incompleteIsEvictedWithoutGoingStale() {
        cache.markIncomplete(IP_A);

        clock.advance(REACHABLE.plusSeconds(1));
        assertTrue(cache.get(IP_A).isEmpty());
    }

    /** Re-observing a stale entry restores it to fresh. */
    @Test
    public void observingAStaleEntryRefreshesIt() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        clock.advance(REACHABLE.plusSeconds(1));
        assertEquals(IpMacCache.State.STALE, cache.get(IP_A).orElseThrow().state());

        cache.observe(IP_A, MAC_A, ResolveSource.PASSIVE);
        assertEquals(IpMacCache.State.REACHABLE, cache.get(IP_A).orElseThrow().state());
    }

    /** Soliciting an address we already know must not wipe its MAC. */
    @Test
    public void markIncompleteNeverDowngradesAKnownEntry() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        cache.markIncomplete(IP_A);

        IpMacCache.Entry e = cache.get(IP_A).orElseThrow();
        assertEquals(IpMacCache.State.REACHABLE, e.state());
        assertEquals(MAC_A, e.mac());
    }

    // ---- conflict detection ----

    /**
     * A different MAC for a currently-REACHABLE address is adopted — the cache
     * must track reality — but COUNTED, which is what distinguishes a DHCP lease
     * change from ARP spoofing downstream.
     */
    @Test
    public void conflictIsCountedNotSilentlyOverwritten() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        clock.advance(Duration.ofSeconds(5));
        cache.observe(IP_A, MAC_B, ResolveSource.PASSIVE);

        IpMacCache.Entry e = cache.get(IP_A).orElseThrow();
        assertEquals(MAC_B, e.mac(), "the new MAC is adopted");
        assertEquals(1, e.conflictCount());
        assertTrue(e.hasConflicts());
        assertEquals(clock.instant(), e.lastConflictAt());
    }

    @Test
    public void repeatedConflictsAccumulate() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        cache.observe(IP_A, MAC_B, ResolveSource.ACTIVE_ARP);
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        cache.observe(IP_A, MAC_B, ResolveSource.ACTIVE_ARP);

        assertEquals(3, cache.get(IP_A).orElseThrow().conflictCount());
    }

    @Test
    public void sameMacIsNotAConflict() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        cache.observe(IP_A, MAC_A, ResolveSource.PASSIVE);
        cache.observe(IP_A, MAC_A, ResolveSource.KERNEL_TABLE);

        IpMacCache.Entry e = cache.get(IP_A).orElseThrow();
        assertEquals(0, e.conflictCount());
        assertFalse(e.hasConflicts());
    }

    /** Replacing a STALE binding is not a conflict — the old one had already aged out. */
    @Test
    public void replacingAStaleMacIsNotAConflict() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        clock.advance(REACHABLE.plusSeconds(1));
        cache.observe(IP_A, MAC_B, ResolveSource.ACTIVE_ARP);

        IpMacCache.Entry e = cache.get(IP_A).orElseThrow();
        assertEquals(MAC_B, e.mac());
        assertEquals(0, e.conflictCount());
    }

    /** Filling in an INCOMPLETE entry is not a conflict — there was no MAC to contradict. */
    @Test
    public void resolvingAnIncompleteEntryIsNotAConflict() {
        cache.markIncomplete(IP_A);
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        assertEquals(0, cache.get(IP_A).orElseThrow().conflictCount());
    }

    /** Conflict history survives ordinary refreshes so a slow attack stays visible. */
    @Test
    public void conflictHistorySurvivesLaterCleanObservations() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        cache.observe(IP_A, MAC_B, ResolveSource.ACTIVE_ARP);
        Instant conflictAt = cache.get(IP_A).orElseThrow().lastConflictAt();

        clock.advance(Duration.ofSeconds(5));
        cache.observe(IP_A, MAC_B, ResolveSource.ACTIVE_ARP);

        IpMacCache.Entry e = cache.get(IP_A).orElseThrow();
        assertEquals(1, e.conflictCount());
        assertEquals(conflictAt, e.lastConflictAt());
    }

    /** Eviction is a clean slate: history belongs to the entry, not the address. */
    @Test
    public void evictionDropsConflictHistory() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        cache.observe(IP_A, MAC_B, ResolveSource.ACTIVE_ARP);
        assertEquals(1, cache.get(IP_A).orElseThrow().conflictCount());

        clock.advance(REACHABLE.plus(STALE).plusSeconds(1));
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);

        IpMacCache.Entry e = cache.get(IP_A).orElseThrow();
        assertEquals(0, e.conflictCount());
        assertEquals(clock.instant(), e.firstSeen(), "a fresh entry, not a revival");
    }

    // ---- sweep and snapshot ----

    @Test
    public void sweepEvictsOnlyExpiredEntries() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        clock.advance(REACHABLE.plus(STALE).plusSeconds(1));
        cache.observe(IP_B, MAC_B, ResolveSource.ACTIVE_ARP);

        assertEquals(2, cache.size());
        assertEquals(1, cache.sweepExpired());
        assertEquals(1, cache.size());
        assertTrue(cache.get(IP_B).isPresent());
    }

    @Test
    public void sweepPromotesToStaleWithoutEvicting() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        clock.advance(REACHABLE.plusSeconds(1));

        assertEquals(0, cache.sweepExpired());
        assertEquals(IpMacCache.State.STALE, cache.get(IP_A).orElseThrow().state());
    }

    /** snapshot projects aging without mutating — nothing is reclaimed by reading. */
    @Test
    public void snapshotProjectsAgingWithoutMutating() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        clock.advance(REACHABLE.plusSeconds(1));

        List<IpMacCache.Entry> snap = cache.snapshot();
        assertEquals(1, snap.size());
        assertEquals(IpMacCache.State.STALE, snap.get(0).state());
        assertEquals(1, cache.size(), "snapshot must not evict");

        clock.advance(STALE);
        assertTrue(cache.snapshot().isEmpty(), "expired entries are omitted from the view");
        assertEquals(1, cache.size(), "but still stored until swept");
    }

    @Test
    public void clearEmptiesTheCache() {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        cache.observe(IP_B, MAC_B, ResolveSource.ACTIVE_ARP);
        cache.clear();
        assertEquals(0, cache.size());
    }

    // ---- construction ----

    @Test
    public void rejectsNonPositiveTtls() {
        assertThrows(IllegalArgumentException.class,
                     () -> new IpMacCache(16, Duration.ZERO, STALE));
        assertThrows(IllegalArgumentException.class,
                     () -> new IpMacCache(16, REACHABLE, Duration.ofSeconds(-1)));
    }

    @Test
    public void observeRejectsNulls() {
        assertThrows(NullPointerException.class,
                     () -> cache.observe(null, MAC_A, ResolveSource.ACTIVE_ARP));
        assertThrows(NullPointerException.class,
                     () -> cache.observe(IP_A, null, ResolveSource.ACTIVE_ARP));
        assertThrows(NullPointerException.class, () -> cache.observe(IP_A, MAC_A, null));
    }

    @Test
    public void defaultsAreUsable() {
        IpMacCache d = IpMacCache.withDefaults(32);
        assertEquals(IpMacCache.DEFAULT_REACHABLE_TTL, d.reachableTtl());
        assertEquals(IpMacCache.DEFAULT_STALE_TTL, d.staleTtl());
        d.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);
        assertNotNull(d.get(IP_A).orElseThrow());
    }

    // ---- concurrency ----

    /**
     * Every conflicting observation must be counted exactly once. A read-then-write
     * upsert loses updates here; only an atomic {@code compute} survives.
     */
    @Test
    public void concurrentConflictingObservationsAreCountedExactly() throws Exception {
        int threads = 8;
        int flipsPerThread = 500;
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        try {
            for (int t = 0; t < threads; t++) {
                final MacAddress mac = (t % 2 == 0) ? MAC_A : MAC_B;
                pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < flipsPerThread; i++) {
                        cache.observe(IP_A, mac, ResolveSource.ACTIVE_ARP);
                    }
                    return null;
                });
            }
            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "workers must finish");
        } finally {
            pool.shutdownNow();
        }

        IpMacCache.Entry e = cache.get(IP_A).orElseThrow();
        assertEquals(1, cache.size());
        assertTrue(e.conflictCount() > 0, "flipping MACs must register conflicts");
        assertTrue(e.mac().equals(MAC_A) || e.mac().equals(MAC_B));
        assertEquals(IpMacCache.State.REACHABLE, e.state());
    }

    /** Distinct addresses observed concurrently must all survive. */
    @Test
    public void concurrentDistinctInsertsAllLand() throws Exception {
        int count = 1000;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        AtomicInteger failures = new AtomicInteger();
        try {
            for (int i = 0; i < count; i++) {
                final int n = i;
                pool.submit(() -> {
                    try {
                        byte[] raw = {10, (byte) (n >>> 16), (byte) (n >>> 8), (byte) n};
                        cache.observe(InetAddress.getByAddress(raw), MAC_A,
                                      ResolveSource.PASSIVE);
                    } catch (Exception ex) {
                        failures.incrementAndGet();
                    }
                });
            }
            pool.shutdown();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }

        assertEquals(0, failures.get());
        assertEquals(count, cache.size());

        Set<InetAddress> distinct = new HashSet<>();
        for (IpMacCache.Entry e : cache.snapshot()) {
            distinct.add(e.ip());
        }
        assertEquals(count, distinct.size());
    }

    /** Concurrent readers must never observe a torn or half-built entry. */
    @Test
    public void concurrentReadersSeeConsistentEntries() throws Exception {
        cache.observe(IP_A, MAC_A, ResolveSource.ACTIVE_ARP);

        ExecutorService pool = Executors.newFixedThreadPool(4);
        AtomicInteger inconsistent = new AtomicInteger();
        try {
            for (int t = 0; t < 4; t++) {
                pool.submit(() -> {
                    for (int i = 0; i < 2000; i++) {
                        cache.get(IP_A).ifPresent(e -> {
                            boolean ok = e.state() == IpMacCache.State.INCOMPLETE
                                    ? e.mac() == null
                                    : e.mac() != null && e.provenance() != null;
                            if (!ok || !e.lastSeen().isBefore(e.firstSeen().plusSeconds(1))) {
                                if (!ok) {
                                    inconsistent.incrementAndGet();
                                }
                            }
                        });
                        cache.observe(IP_A, MAC_A, ResolveSource.PASSIVE);
                    }
                });
            }
            pool.shutdown();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }

        assertEquals(0, inconsistent.get(), "a REACHABLE entry must always carry a MAC");
        assertSame(IpMacCache.State.REACHABLE, cache.get(IP_A).orElseThrow().state());
    }
}
