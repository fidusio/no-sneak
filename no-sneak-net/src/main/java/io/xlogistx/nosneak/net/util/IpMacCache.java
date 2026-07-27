package io.xlogistx.nosneak.net.util;

import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.ResolveSource;

import java.net.InetAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The live IP-to-MAC table for ONE interface binding.
 * <p>
 * Per-binding by design: {@link java.net.Inet6Address#equals} compares the
 * sixteen address bytes and ignores the scope id, so {@code fe80::1%eth0} and
 * {@code fe80::1%eth1} would collide in a shared cache. Per-binding ownership
 * makes that harmless. A cross-interface cache would have to key on
 * {@code (ifIndex, address)}.
 * <p>
 * Never call {@link InetAddress#getHostName()} anywhere near this class — it
 * triggers reverse DNS. {@code equals}, {@code hashCode} and {@code toString} do
 * not, and nothing here calls it.
 * <p>
 * Thread-safe through {@link ConcurrentHashMap}'s atomic operations. Every
 * mutation goes through {@code compute}, never a read-then-write pair: a
 * {@code getOrDefault} followed by {@code put} would lose concurrent updates and
 * mis-count conflicts.
 */
public final class IpMacCache {

    /** Default freshness window before an entry is considered stale. */
    public static final Duration DEFAULT_REACHABLE_TTL = Duration.ofSeconds(30);

    /** Default additional window a stale entry survives before eviction. */
    public static final Duration DEFAULT_STALE_TTL = Duration.ofMinutes(5);

    /**
     * One cached neighbour.
     *
     * @param mac            null only while {@link State#INCOMPLETE}
     * @param provenance     null only while {@link State#INCOMPLETE}
     * @param conflictCount  times a DIFFERENT MAC was reported for this IP while the
     *                       entry was {@link State#REACHABLE}. On a security appliance
     *                       that is either legitimate DHCP/failover or ARP spoofing, and
     *                       the fingerprinting layer wants to know
     * @param lastConflictAt null when {@code conflictCount == 0}
     */
    public record Entry(
            InetAddress ip,
            MacAddress mac,
            State state,
            ResolveSource provenance,
            Instant firstSeen,
            Instant lastSeen,
            int conflictCount,
            Instant lastConflictAt) {

        public boolean hasMac() {
            return mac != null;
        }

        public boolean hasConflicts() {
            return conflictCount > 0;
        }
    }

    /**
     * {@code INCOMPLETE} solicited but unanswered, {@code REACHABLE} fresh,
     * {@code STALE} past its freshness window but not yet evicted.
     */
    public enum State { INCOMPLETE, REACHABLE, STALE }

    private final ConcurrentHashMap<InetAddress, Entry> map;
    private final Duration reachableTtl;
    private final Duration staleTtl;
    private final Clock clock;

    /**
     * @param expectedHosts sizing hint. NOTE: {@link ConcurrentHashMap}'s one-arg
     *                      constructor ALREADY applies 1.5x headroom internally
     *                      ({@code sizeCtl = tableSizeFor(n + (n >>> 1) + 1)}). Do NOT
     *                      apply the {@code HashMap} {@code n / 0.75} idiom on top of it —
     *                      that yields roughly twice the intended table
     */
    public IpMacCache(int expectedHosts, Duration reachableTtl, Duration staleTtl) {
        this(expectedHosts, reachableTtl, staleTtl, Clock.systemUTC());
    }

    /**
     * @param clock injected so aging can be tested deterministically instead of by
     *             sleeping. Note this is wall-clock time, because {@link Entry}
     *             timestamps are {@link Instant}s — a large NTP step backwards will
     *             make entries look younger than they are. Harmless for a cache;
     *             RTT measurement deliberately uses {@code System.nanoTime()} instead
     */
    public IpMacCache(int expectedHosts, Duration reachableTtl, Duration staleTtl, Clock clock) {
        if (reachableTtl == null || reachableTtl.isNegative() || reachableTtl.isZero()) {
            throw new IllegalArgumentException("reachableTtl must be positive");
        }
        if (staleTtl == null || staleTtl.isNegative() || staleTtl.isZero()) {
            throw new IllegalArgumentException("staleTtl must be positive");
        }
        this.map = new ConcurrentHashMap<>(Math.max(16, expectedHosts));
        this.reachableTtl = reachableTtl;
        this.staleTtl = staleTtl;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** A cache with the {@link #DEFAULT_REACHABLE_TTL} / {@link #DEFAULT_STALE_TTL} windows. */
    public static IpMacCache withDefaults(int expectedHosts) {
        return new IpMacCache(expectedHosts, DEFAULT_REACHABLE_TTL, DEFAULT_STALE_TTL);
    }

    /**
     * Lookup with lazy aging: the returned entry reflects any
     * {@code REACHABLE -> STALE} transition due at this instant, and an entry past
     * eviction is removed and reported absent.
     */
    public Optional<Entry> get(InetAddress ip) {
        if (ip == null) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        return Optional.ofNullable(map.compute(ip, (k, existing) -> aged(existing, now)));
    }

    /**
     * Records an active, passive, or kernel-table observation, atomically.
     * <p>
     * CONFLICT HANDLING: when the entry is currently {@link State#REACHABLE} with a
     * DIFFERENT MAC, the new MAC is adopted — the cache must track reality, since
     * DHCP and failover legitimately move an address — but the event is COUNTED and
     * timestamped rather than silently overwritten. A non-zero
     * {@link Entry#conflictCount()} is what the fingerprinting layer reads to tell
     * a lease change from ARP spoofing.
     * <p>
     * Replacing the MAC on a {@link State#STALE} entry is NOT a conflict: the old
     * binding had already aged out, so there is nothing to contradict.
     */
    public void observe(InetAddress ip, MacAddress mac, ResolveSource src) {
        Objects.requireNonNull(ip, "ip");
        Objects.requireNonNull(mac, "mac");
        Objects.requireNonNull(src, "src");
        Instant now = clock.instant();

        map.compute(ip, (k, existing) -> {
            Entry current = aged(existing, now);
            if (current == null) {
                return new Entry(ip, mac, State.REACHABLE, src, now, now, 0, null);
            }
            boolean conflict = current.state() == State.REACHABLE
                    && current.hasMac()
                    && !current.mac().equals(mac);
            return new Entry(
                    ip,
                    mac,
                    State.REACHABLE,
                    src,
                    current.firstSeen(),
                    now,
                    conflict ? current.conflictCount() + 1 : current.conflictCount(),
                    conflict ? now : current.lastConflictAt());
        });
    }

    /**
     * Marks an in-flight solicitation.
     * <p>
     * INFORMATIONAL ONLY — this does NOT dedupe concurrent resolves. Deduplication
     * belongs in the in-flight correlation map, where a second caller can
     * {@code computeIfAbsent} onto the first caller's future and actually await a
     * result; a cache entry gives it nothing to wait on.
     * <p>
     * Never downgrades a known entry: soliciting an address we already have a MAC
     * for leaves that MAC in place.
     */
    public void markIncomplete(InetAddress ip) {
        Objects.requireNonNull(ip, "ip");
        Instant now = clock.instant();

        map.compute(ip, (k, existing) -> {
            Entry current = aged(existing, now);
            return current != null
                    ? current
                    : new Entry(ip, null, State.INCOMPLETE, null, now, now, 0, null);
        });
    }

    /**
     * Applies aging to every entry, promoting to {@link State#STALE} and evicting
     * where due. Intended for an optional scheduled daemon sweep;
     * {@link #get(InetAddress)} already ages lazily, so this is an optimisation
     * rather than a correctness requirement.
     *
     * @return the number of entries evicted
     */
    public int sweepExpired() {
        Instant now = clock.instant();
        AtomicInteger evicted = new AtomicInteger();
        for (InetAddress ip : List.copyOf(map.keySet())) {
            map.compute(ip, (k, existing) -> {
                Entry next = aged(existing, now);
                if (existing != null && next == null) {
                    evicted.incrementAndGet();
                }
                return next;
            });
        }
        return evicted.get();
    }

    /**
     * A point-in-time copy for the admin UI, with aging applied as a PROJECTION —
     * entries are reported at the state they have reached, and ones past eviction
     * are omitted, but nothing is mutated. Use {@link #sweepExpired()} to actually
     * reclaim.
     */
    public List<Entry> snapshot() {
        Instant now = clock.instant();
        return map.values().stream()
                  .map(e -> aged(e, now))
                  .filter(Objects::nonNull)
                  .toList();
    }

    /**
     * The number of stored entries, INCLUDING any that are past eviction but not
     * yet swept. {@link #snapshot()} gives the live count.
     */
    public int size() {
        return map.size();
    }

    /** Drops every entry. */
    public void clear() {
        map.clear();
    }

    public Duration reachableTtl() {
        return reachableTtl;
    }

    public Duration staleTtl() {
        return staleTtl;
    }

    /**
     * The aging projection, shared by every read and write path so they can never
     * disagree about what an entry's state is at a given instant.
     *
     * @return the entry at its current state, or null when it should be evicted
     */
    private Entry aged(Entry e, Instant now) {
        if (e == null) {
            return null;
        }
        Duration age = Duration.between(e.lastSeen(), now);

        // An INCOMPLETE entry has no MAC, so there is nothing for it to go stale
        // with — an unanswered solicitation is simply dropped.
        if (e.state() == State.INCOMPLETE) {
            return age.compareTo(reachableTtl) > 0 ? null : e;
        }
        if (age.compareTo(reachableTtl.plus(staleTtl)) > 0) {
            return null;
        }
        if (age.compareTo(reachableTtl) > 0 && e.state() != State.STALE) {
            return new Entry(e.ip(), e.mac(), State.STALE, e.provenance(),
                             e.firstSeen(), e.lastSeen(),
                             e.conflictCount(), e.lastConflictAt());
        }
        return e;
    }
}
