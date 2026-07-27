package io.xlogistx.nosneak.net.common;

/**
 * What kind of frame produced an {@link ObservedNeighbor}.
 * <p>
 * A frame is classified {@link #GRATUITOUS_ARP} when its sender protocol address
 * equals its target protocol address, for either operation — that check takes
 * priority over the request/reply distinction.
 */
public enum ObservationKind {

    ARP_REQUEST,
    ARP_REPLY,
    GRATUITOUS_ARP,
    NDP_NS,
    NDP_NA
}
