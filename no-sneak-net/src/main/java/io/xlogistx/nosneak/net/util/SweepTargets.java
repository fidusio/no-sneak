package io.xlogistx.nosneak.net.util;

import io.xlogistx.nosneak.net.common.CidrRange;
import io.xlogistx.nosneak.net.common.NicBinding;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.List;

/**
 * Which addresses of a swept range may be probed at all — the other half of
 * {@link SweepDriver}, which decides <i>when</i>.
 * <p>
 * The wire-discipline rule is that a directed broadcast is never pinged: every host
 * on that segment answers at once, which is amplification and reads as an attack on a
 * security appliance. {@link NicBinding#isNetworkOrBroadcast} enforces it for the
 * INTERFACE's own subnets, deliberately against the interface's real prefix so that a
 * {@code /29} swept inside a {@code /24} does not lose two legitimate hosts to a guess.
 * That left a gap (§13.21 S12): a range that is off-link, or wider than the interface's
 * prefix, has edges the interface knows nothing about — {@code sweep 10.1.0.0/24} from
 * {@code 10.0.0.61/24} echoed {@code 10.1.0.0} and {@code 10.1.0.255} through the
 * gateway, gated only by the router's directed-broadcast setting.
 * <p>
 * The rule here: the range's own first and last address are ALSO withheld unless one of
 * the interface's IPv4 prefixes covers the whole range, in which case the interface's
 * own rule already knows better (the range is inside a subnet whose real edges are the
 * ones that matter). IPv4 only, and only for prefixes of {@code /30} or shorter —
 * {@code /31} (RFC 3021) and {@code /32} designate no spare addresses, and IPv6 has no
 * broadcast (the all-zero interface identifier is subnet-router anycast, answered by at
 * most one router). Nothing here ever ADDS an address; it only removes.
 */
public final class SweepTargets {

    private SweepTargets() {
    }

    /** True for the range's own network or last address, IPv4 with prefix ≤ 30 only. */
    public static boolean isRangeEdge(CidrRange range, InetAddress target) {
        if (range.isIpv6() || range.prefixLength() > 30 || !(target instanceof Inet4Address)) {
            return false;
        }
        return target.equals(range.networkAddress()) || target.equals(range.lastAddress());
    }

    /**
     * True when one of the binding's IPv4 subnets contains the ENTIRE range — its
     * prefix is at least as short as the range's and the range's network address is
     * on-link. Then the range's edges are ordinary hosts (or the interface's own
     * edges, which {@link NicBinding#isNetworkOrBroadcast} already withholds).
     */
    public static boolean coversWholeRange(NicBinding binding, CidrRange range) {
        if (range.isIpv6()) {
            return false;
        }
        for (NicBinding.LocalAddress local : binding.ipv4()) {
            if (local.prefixLength() <= range.prefixLength()
                    && local.onLink(range.networkAddress())) {
                return true;
            }
        }
        return false;
    }

    /** The one predicate every sweep applies: interface edges, then range edges. */
    public static boolean mustSkip(NicBinding binding, CidrRange range, InetAddress target) {
        return binding.isNetworkOrBroadcast(target)
                || (isRangeEdge(range, target) && !coversWholeRange(binding, range));
    }

    /** Every address of {@code range} that a sweep through {@code binding} may probe, in order. */
    public static List<InetAddress> probeable(NicBinding binding, CidrRange range) {
        return range.hosts().filter(t -> !mustSkip(binding, range, t)).toList();
    }
}
