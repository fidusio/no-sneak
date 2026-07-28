package io.xlogistx.nosneak.net.spike;

import io.xlogistx.nosneak.net.codecs.ArpPacket;
import io.xlogistx.nosneak.net.codecs.EthernetFrame;
import io.xlogistx.nosneak.net.common.DiscoveryException;
import io.xlogistx.nosneak.net.common.MacAddress;
import io.xlogistx.nosneak.net.common.NicBinding;
import io.xlogistx.nosneak.net.pcap.PcapDevices;
import io.xlogistx.nosneak.net.pcap.PcapHandle;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Throwaway experiment: does a host that ignores BROADCAST ARP answer a UNICAST
 * ARP request, over pcap on Windows?
 *
 * <pre>
 *   WindowsArpSpike &lt;targetIp&gt; &lt;hintMac&gt; [interfaceName]
 *   WindowsArpSpike 10.0.0.108 94:e6:ba:4d:66:1b
 * </pre>
 * <p>
 * This reproduces the §13.12 Linux measurement on the Windows backend's transport.
 * There, a host answered 0 of 3 broadcast requests and 3 of 3 unicast requests to
 * the same MAC, because access points buffer broadcast against the DTIM interval
 * and commonly suppress or proxy it — so a station stays fully reachable by unicast
 * while never seeing a broadcast frame. Linux was fixed to send unicast whenever
 * {@code IpMacCache} holds a hint; {@code WindowsPcapBackend.solicit()} still sends
 * broadcast only, on every one of its three attempts.
 * <p>
 * The point of running it is that the fix is NOT a copy-paste port. On Linux the
 * hint bootstraps itself: ICMP goes through the kernel, which does its own unicast
 * neighbour probing, so a ping succeeds and the reply frame teaches us the MAC. On
 * Windows the ping is injected at layer 2 and needs the MAC first, so it fails with
 * HOST_UNREACHABLE and teaches us nothing. Before building a hint source, confirm a
 * hint is worth having.
 * <p>
 * SENDS ONLY ARP REQUESTS — six frames, three of each kind. It resolves nothing,
 * caches nothing, and changes no state on this machine or the target.
 * <p>
 * Deliberately self-contained and single-threaded-plus-a-reader: no
 * {@code HostDiscovery}, no factory, no executor injection. A spike that shares
 * machinery with the code under suspicion cannot exonerate it.
 */
public final class WindowsArpSpike {

    private static final int ATTEMPTS = 3;
    private static final Duration BETWEEN_SENDS = Duration.ofSeconds(1);
    private static final Duration SETTLE = Duration.ofSeconds(2);

    /** A reply we saw, with the offset from the phase start that produced it. */
    private record Reply(MacAddress mac, long afterMillis) {
    }

    private WindowsArpSpike() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("""
                    usage: WindowsArpSpike <targetIp> <hintMac> [interfaceName]
                      e.g. WindowsArpSpike 10.0.0.108 94:e6:ba:4d:66:1b

                    Sends 3 broadcast ARP requests, then 3 unicast requests to hintMac,
                    and counts the replies from targetIp. Nothing else is transmitted.""");
            System.exit(2);
        }
        InetAddress target = InetAddress.ofLiteral(args[0]);
        MacAddress hint = MacAddress.parse(args[1]);
        NetworkInterface nif = args.length > 2
                ? NetworkInterface.getByName(args[2])
                : interfaceFor(target);
        if (nif == null) {
            System.err.println("No interface has " + target.getHostAddress() + " on-link");
            System.exit(1);
        }

        List<PcapDevices.Device> devices = PcapDevices.findAll();
        NicBinding binding = NicBinding.from(nif, candidate -> {
            try {
                return PcapDevices.requireDeviceName(devices, candidate);
            } catch (DiscoveryException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        });
        byte[] senderIp = binding.sourceFor(target).orElseThrow().address().getAddress();

        System.out.println("interface : " + binding.javaName() + "  " + binding.hardwareAddress());
        System.out.println("device    : " + binding.backendDeviceName());
        System.out.println("source    : " + InetAddress.getByAddress(senderIp).getHostAddress());
        System.out.println("target    : " + target.getHostAddress());
        System.out.println("hint mac  : " + hint);
        System.out.println();

        // Non-promiscuous: a reply to our own request is addressed to us, so
        // promiscuous mode would only add noise and a detectable footprint.
        try (PcapHandle handle = PcapHandle.open(binding.backendDeviceName(), false)) {
            handle.setFilter("arp");

            List<Reply> replies = Collections.synchronizedList(new ArrayList<>());
            AtomicBoolean running = new AtomicBoolean(true);
            long[] phaseStart = {System.nanoTime()};

            Thread reader = new Thread(() -> {
                while (running.get()) {
                    try {
                        byte[] frame = handle.nextPacket();
                        if (frame == null) {
                            continue;   // timeout tick
                        }
                        EthernetFrame.View eth =
                                EthernetFrame.parse(frame, 0, frame.length).orElse(null);
                        if (eth == null || !eth.isArp()) {
                            continue;
                        }
                        ArpPacket.parse(frame, eth.payloadOffset(), eth.payloadLength())
                                 .filter(ArpPacket.ArpView::isReply)
                                 .filter(arp -> java.util.Arrays.equals(arp.spa(),
                                                                        target.getAddress()))
                                 .ifPresent(arp -> replies.add(new Reply(
                                         arp.sha(),
                                         (System.nanoTime() - phaseStart[0]) / 1_000_000)));
                    } catch (DiscoveryException e) {
                        if (running.get()) {
                            System.err.println("reader stopped: " + e.getMessage());
                        }
                        return;
                    }
                }
            }, "arp-spike-reader");
            reader.setDaemon(true);
            reader.start();

            int broadcast = phase(handle, binding, senderIp, target, MacAddress.BROADCAST,
                                  "BROADCAST", replies, phaseStart);
            int unicast = phase(handle, binding, senderIp, target, hint,
                                "UNICAST  ", replies, phaseStart);

            running.set(false);
            reader.join(TimeUnit.SECONDS.toMillis(2));

            System.out.println();
            System.out.println("BROADCAST ARP x" + ATTEMPTS + "  ->  " + broadcast + " replies");
            System.out.println("UNICAST   ARP x" + ATTEMPTS + "  ->  " + unicast + " replies");
            System.out.println();
            System.out.println(verdict(broadcast, unicast));
        }
    }

    /** Sends {@link #ATTEMPTS} requests to one destination MAC and counts what came back. */
    private static int phase(PcapHandle handle, NicBinding binding, byte[] senderIp,
                             InetAddress target, MacAddress destination, String label,
                             List<Reply> replies, long[] phaseStart) throws InterruptedException {
        replies.clear();
        phaseStart[0] = System.nanoTime();
        byte[] arp = ArpPacket.request(binding.hardwareAddress(), senderIp, target.getAddress());
        byte[] frame = EthernetFrame.build(destination, binding.hardwareAddress(),
                                           EthernetFrame.ETHERTYPE_ARP, arp);
        for (int i = 0; i < ATTEMPTS; i++) {
            boolean sent = handle.send(frame);
            System.out.printf("%s  %s  who-has %s tell %s%s%n",
                              Instant.now(), label, target.getHostAddress(),
                              addr(senderIp), sent ? "" : "   [SEND FAILED: " + handle.lastError() + "]");
            Thread.sleep(BETWEEN_SENDS.toMillis());
        }
        Thread.sleep(SETTLE.toMillis());
        synchronized (replies) {
            for (Reply r : replies) {
                System.out.printf("            reply from %s after %d ms%n", r.mac(), r.afterMillis());
            }
            return replies.size();
        }
    }

    private static String verdict(int broadcast, int unicast) {
        if (unicast > 0 && broadcast == 0) {
            return """
                    CONFIRMED: the host ignores broadcast ARP and answers unicast.
                    This is the section 13.12 case on the Windows transport, so the unicast-hint
                    branch is worth porting to WindowsPcapBackend.solicit() - and it needs a hint
                    source, since nothing on this platform learns the MAC on its own.""";
        }
        if (unicast > 0) {
            return """
                    BOTH WORK: broadcast was answered too, so this host is not suppressing it right
                    now. Whatever made resolve() time out is something else - re-run when the
                    failure is actually reproducing, and check the BPF filter and the reply demux.""";
        }
        if (broadcast > 0) {
            return """
                    UNEXPECTED: broadcast answered and unicast did not. Suspect a stale hint MAC -
                    the host may have moved - rather than a transport problem.""";
        }
        return """
                NEITHER: no reply to either form. The host may be off, or injection may not be
                working on this adapter at all. Check that the interface is not capture-only
                (hostscan list shows its capabilities) before drawing any conclusion about ARP.""";
    }

    private static String addr(byte[] ipv4) {
        try {
            return InetAddress.getByAddress(ipv4).getHostAddress();
        } catch (Exception e) {
            return java.util.Arrays.toString(ipv4);
        }
    }

    private static NetworkInterface interfaceFor(InetAddress target) throws Exception {
        for (NetworkInterface nif : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!nif.isUp() || nif.isLoopback() || nif.getInterfaceAddresses().isEmpty()) {
                continue;
            }
            for (java.net.InterfaceAddress a : nif.getInterfaceAddresses()) {
                if (a.getAddress().getClass() == target.getClass()
                    && new NicBinding.LocalAddress(a.getAddress(), a.getNetworkPrefixLength())
                            .onLink(target)) {
                    return nif;
                }
            }
        }
        return null;
    }
}
