package io.xlogistx.nosneak.net.common;

import io.xlogistx.nosneak.net.platform.darwin.DarwinIcmpPing;
import io.xlogistx.nosneak.net.platform.darwin.DarwinPcapBackend;
import io.xlogistx.nosneak.net.platform.linux.LinuxHostDiscovery;
import io.xlogistx.nosneak.net.platform.linux.LinuxIcmpPing;
import io.xlogistx.nosneak.net.pcap.PcapDevices;
import io.xlogistx.nosneak.net.platform.windows.WindowsPcapBackend;

import org.zoxweb.server.task.TaskUtil;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;

/**
 * Selects a backend by {@code os.name} and returns it fully wired.
 * <p>
 * This class is the ONLY place that knows how {@link ICMPPing} and
 * {@link HostDiscovery} are connected, and that is what makes the set-once
 * collaborator safe.
 */
public final class HostDiscoveryFactory {

    /** Architectures with an FFM linker implementation. 32-bit is unsupported by the platform. */
    private static final Set<String> SUPPORTED_ARCH =
            Set.of("amd64", "x86_64", "aarch64", "arm64");

    private HostDiscoveryFactory() {
    }

    /**
     * Opens one L2 backend per interface, plus a pinger, fully wired.
     * <p>
     * WIRING ORDER — the whole reason this class exists:
     * <ol>
     *   <li>open a {@link HostDiscovery} per {@link NetworkInterface}</li>
     *   <li>construct the {@link ICMPPing} — standalone on Linux and macOS; on
     *       Windows over the list from step 1, where the returned pinger IS one of
     *       those objects rather than a new one</li>
     *   <li>set-once inject the pinger into each backend via
     *       {@link HostDiscovery#attachPinger}</li>
     *   <li>only now return, so no caller can observe a half-built object or a
     *       {@code capabilities()} that later changes</li>
     * </ol>
     * If any interface fails to open, everything already opened is closed before
     * the exception propagates — a partially-built {@link Discovery} is never
     * leaked.
     *
     * @param scheduler  arms per-probe and per-solicitation timeouts
     * @param dispatcher runs user callbacks, never a reader thread
     * @throws DiscoveryException on an unsupported architecture or platform, missing
     *                            privilege, or an unloadable native library
     */
    public static Discovery open(List<NetworkInterface> nics,
                                 ScheduledExecutorService scheduler,
                                 ExecutorService dispatcher) throws DiscoveryException {
        requireSupportedArch();
        Objects.requireNonNull(nics, "nics");
        Objects.requireNonNull(scheduler, "scheduler");
        Objects.requireNonNull(dispatcher, "dispatcher");
        if (nics.isEmpty()) {
            throw new DiscoveryException("At least one network interface is required");
        }
        Platform platform = Platform.current();

        List<HostDiscovery> backends = new ArrayList<>(nics.size());
        try {
            // 1. per-interface backends
            Object context = platform.newContext();
            for (NetworkInterface nif : nics) {
                backends.add(platform.openBackend(nif, context, scheduler, dispatcher));
            }
            // 2. the pinger, over those backends where the platform needs them
            ICMPPing ping = platform.openPinger(backends, scheduler, dispatcher);
            // 3. set-once injection, still before publication
            for (HostDiscovery backend : backends) {
                backend.attachPinger(ping);
            }
            // 4. publish
            return new Discovery(backends, ping);
        } catch (DiscoveryException | RuntimeException e) {
            closeQuietly(backends);
            throw e;
        }
    }

    /**
     * Same, on the process-wide zoxweb pools.
     * <p>
     * NOTE the scheduler is {@code TaskUtil.defaultTaskScheduler()} and NOT
     * {@code defaultTaskProcessor()} — the latter is a plain
     * {@link ExecutorService} and cannot arm a timeout.
     * <p>
     * Executors supplied this way are BORROWED: {@link Discovery#close()} will not
     * shut them down.
     */
    public static Discovery open(List<NetworkInterface> nics) throws DiscoveryException {
        return open(nics, TaskUtil.defaultTaskScheduler(), TaskUtil.defaultTaskProcessor());
    }

    /** Single-interface convenience. Same wiring, one NIC. */
    public static Discovery open(NetworkInterface nif) throws DiscoveryException {
        return open(List.of(Objects.requireNonNull(nif, "nif")));
    }

    /** Convenience: picks the interface owning a given local address. */
    public static Discovery openForLocalAddress(InetAddress local) throws DiscoveryException {
        Objects.requireNonNull(local, "local");
        try {
            NetworkInterface nif = NetworkInterface.getByInetAddress(local);
            if (nif == null) {
                throw new DiscoveryException(
                        "No interface owns local address " + local.getHostAddress());
            }
            return open(nif);
        } catch (SocketException e) {
            throw new DiscoveryException("Could not enumerate interfaces", e);
        }
    }

    /**
     * ICMP only — no interface, no ARP/NDP, no cache. Two reader threads for the
     * whole JVM.
     * <p>
     * UNSUPPORTED ON WINDOWS: pcap cannot ping without a device and a resolved
     * destination MAC. Throws there, naming the reason; use {@link #open(List)}
     * instead.
     */
    public static ICMPPing openIcmpOnly(ScheduledExecutorService scheduler,
                                        ExecutorService dispatcher) throws DiscoveryException {
        requireSupportedArch();
        Objects.requireNonNull(scheduler, "scheduler");
        Objects.requireNonNull(dispatcher, "dispatcher");
        return Platform.current().openStandalonePinger(scheduler, dispatcher);
    }

    /** Same, on the process-wide zoxweb pools. */
    public static ICMPPing openIcmpOnly() throws DiscoveryException {
        return openIcmpOnly(TaskUtil.defaultTaskScheduler(), TaskUtil.defaultTaskProcessor());
    }

    /**
     * Every interface that is up, has an address, and is not loopback — the usual
     * argument to {@link #open(List)}.
     */
    public static List<NetworkInterface> usableInterfaces() throws DiscoveryException {
        try {
            List<NetworkInterface> out = new ArrayList<>();
            for (NetworkInterface nif : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (nif.isUp() && !nif.isLoopback() && !nif.getInterfaceAddresses().isEmpty()) {
                    out.add(nif);
                }
            }
            return out;
        } catch (SocketException e) {
            throw new DiscoveryException("Could not enumerate network interfaces", e);
        }
    }

    /**
     * Fails fast on an architecture with no FFM linker, rather than letting an
     * {@link UnsupportedOperationException} surface from the first downcall setup.
     */
    static void requireSupportedArch() throws DiscoveryException {
        String arch = System.getProperty("os.arch", "");
        if (!SUPPORTED_ARCH.contains(arch)) {
            throw new DiscoveryException(
                    "Unsupported architecture '" + arch + "': host discovery requires 64-bit "
                    + SUPPORTED_ARCH + ". The FFM API has no 32-bit linker implementation.");
        }
    }

    private static void closeQuietly(List<HostDiscovery> backends) {
        for (HostDiscovery backend : backends) {
            try {
                backend.close();
            } catch (RuntimeException ignored) {
                // already unwinding; nothing useful to add
            }
        }
    }

    /** Backend selection, and the per-platform half of the wiring order. */
    private enum Platform {

        LINUX {
            @Override
            HostDiscovery openBackend(NetworkInterface nif, Object context,
                                      ScheduledExecutorService s, ExecutorService d)
                    throws DiscoveryException {
                NicBinding binding;
                try {
                    // The device name is the Java name on Linux; only pcap needs a
                    // separate namespace.
                    binding = NicBinding.from(nif, NetworkInterface::getName);
                } catch (SocketException e) {
                    throw new DiscoveryException("Could not read interface " + nif.getName(), e);
                }
                // Promiscuous mode stays off until observe() asks for it: it raises
                // capture volume substantially and is detectable on the segment.
                return LinuxHostDiscovery.open(binding, s, d, false);
            }

            @Override
            ICMPPing openStandalonePinger(ScheduledExecutorService s, ExecutorService d)
                    throws DiscoveryException {
                return LinuxIcmpPing.open(s, d);
            }
        },

        MACOS {
            /** Enumerated once per open() call, not once per interface. */
            @Override
            Object newContext() throws DiscoveryException {
                return PcapDevices.findAll();
            }

            /**
             * Layer 2 over libpcap, NOT the §7.3 kernel neighbour table.
             * <p>
             * §7.3's ABI gate is retired rather than passed. libpcap is the BPF wrapper,
             * so the variadic {@code ioctl} hazard §2.2 avoided lives inside C where it
             * is already solved, and seeing the wire directly removes any need to parse
             * {@code rt_msghdr}. Needs root — {@code /dev/bpf*} is mode 0600 — whereas
             * ICMP alone still does not.
             */
            @Override
            @SuppressWarnings("unchecked")
            HostDiscovery openBackend(NetworkInterface nif, Object context,
                                      ScheduledExecutorService s, ExecutorService d)
                    throws DiscoveryException {
                List<PcapDevices.Device> devices = (List<PcapDevices.Device>) context;
                NicBinding binding;
                try {
                    binding = NicBinding.from(nif, candidate -> {
                        try {
                            return PcapDevices.requireDeviceName(devices, candidate);
                        } catch (DiscoveryException e) {
                            // The resolver is a Function and cannot declare a checked
                            // exception; unwrapped immediately below.
                            throw new IllegalStateException(e.getMessage(), e);
                        }
                    });
                } catch (SocketException e) {
                    throw new DiscoveryException("Could not read interface " + nif.getName(), e);
                } catch (IllegalStateException e) {
                    throw new DiscoveryException(e.getMessage(), e.getCause());
                }
                // Promiscuous stays off until observe() asks: it raises capture volume
                // substantially and is detectable on the segment.
                return DarwinPcapBackend.open(binding, s, d, false);
            }

            /** ICMP is NOT gated — §7.5 is fully specified and needs no privilege. */
            @Override
            ICMPPing openStandalonePinger(ScheduledExecutorService s, ExecutorService d)
                    throws DiscoveryException {
                return DarwinIcmpPing.open(s, d);
            }
        },

        WINDOWS {
            /** Enumerated once per open() call, not once per interface. */
            @Override
            Object newContext() throws DiscoveryException {
                return PcapDevices.findAll();
            }

            @Override
            @SuppressWarnings("unchecked")
            HostDiscovery openBackend(NetworkInterface nif, Object context,
                                      ScheduledExecutorService s, ExecutorService d)
                    throws DiscoveryException {
                List<PcapDevices.Device> devices = (List<PcapDevices.Device>) context;
                NicBinding binding;
                try {
                    binding = NicBinding.from(nif, candidate -> {
                        try {
                            return PcapDevices.requireDeviceName(devices, candidate);
                        } catch (DiscoveryException e) {
                            // The resolver is a Function and cannot declare a checked
                            // exception; unwrapped immediately below.
                            throw new IllegalStateException(e.getMessage(), e);
                        }
                    });
                } catch (SocketException e) {
                    throw new DiscoveryException("Could not read interface " + nif.getName(), e);
                } catch (IllegalStateException e) {
                    throw new DiscoveryException(e.getMessage(), e.getCause());
                }
                // Promiscuous mode stays off until an observe() subscription needs
                // it: it raises capture volume substantially and is detectable.
                return WindowsPcapBackend.open(binding, s, d, false);
            }

            /**
             * The pinger IS one of the backends (§8.6) — a pcap ping needs ARP, and
             * both roles share one handle, one device, one reader thread.
             */
            @Override
            ICMPPing openPinger(List<HostDiscovery> backends,
                                ScheduledExecutorService s, ExecutorService d)
                    throws DiscoveryException {
                List<WindowsPcapBackend> pcapBackends = new ArrayList<>(backends.size());
                for (HostDiscovery backend : backends) {
                    pcapBackends.add((WindowsPcapBackend) backend);
                }
                for (WindowsPcapBackend backend : pcapBackends) {
                    backend.setPingPeers(pcapBackends);
                }
                // Prefer a binding that can actually inject: a capture-only adapter
                // would reject every send (spec section 8.6).
                for (WindowsPcapBackend backend : pcapBackends) {
                    if (backend.capabilities().icmpV4()) {
                        return backend;
                    }
                }
                return pcapBackends.get(0);
            }

            @Override
            ICMPPing openStandalonePinger(ScheduledExecutorService s, ExecutorService d)
                    throws DiscoveryException {
                throw new DiscoveryException(
                        "openIcmpOnly() is not available on Windows: pcap injects at L2 and "
                        + "cannot send an echo request without a device and a resolved "
                        + "destination MAC. Use open(List<NetworkInterface>) instead.");
            }
        };

        static Platform current() throws DiscoveryException {
            String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
            if (os.contains("linux")) {
                return LINUX;
            }
            if (os.contains("mac") || os.contains("darwin")) {
                return MACOS;
            }
            if (os.contains("windows")) {
                return WINDOWS;
            }
            throw new DiscoveryException(
                    "Unsupported operating system '" + System.getProperty("os.name")
                    + "': host discovery supports Linux, macOS and Windows.");
        }

        /** Platform-wide setup shared by every interface in one open() call. */
        Object newContext() throws DiscoveryException {
            return null;
        }

        abstract HostDiscovery openBackend(NetworkInterface nif, Object context,
                                           ScheduledExecutorService s, ExecutorService d)
                throws DiscoveryException;

        /** Default: a standalone pinger, which is the Linux and macOS shape. */
        ICMPPing openPinger(List<HostDiscovery> backends,
                            ScheduledExecutorService s, ExecutorService d)
                throws DiscoveryException {
            return openStandalonePinger(s, d);
        }

        abstract ICMPPing openStandalonePinger(ScheduledExecutorService s, ExecutorService d)
                throws DiscoveryException;

        static DiscoveryException notYetBuilt(String what, String step) {
            return new DiscoveryException(
                    what + " is not implemented yet (" + step + " of the build order). "
                    + "The public API, codecs and cache are complete and testable; the Windows "
                    + "pcap backend is the only platform backend built so far.");
        }
    }

    /**
     * What {@code open} hands back: the per-NIC backends and the shared pinger.
     * <p>
     * This is the ONLY owner of the pinger's lifetime. It cannot be any one of the
     * per-NIC backends, because closing eth0 would then kill ICMP for eth1.
     * <p>
     * On Windows {@code perInterface.get(0)} and {@link #ping()} may be THE SAME
     * OBJECT.
     */
    public record Discovery(List<HostDiscovery> perInterface, ICMPPing ping)
            implements java.io.Closeable {

        public Discovery {
            perInterface = List.copyOf(perInterface);
        }

        /** The backend bound to the named interface, if it was opened. */
        public Optional<HostDiscovery> forName(String javaName) {
            return perInterface.stream()
                               .filter(h -> h.binding().javaName().equals(javaName))
                               .findFirst();
        }

        /** The first opened backend that has {@code target} on-link, if any. */
        public Optional<HostDiscovery> forTarget(InetAddress target) {
            return perInterface.stream()
                               .filter(h -> h.binding().isOnLink(target))
                               .findFirst();
        }

        /**
         * Closes the pinger AND every backend. Idempotent, and safe when the pinger
         * is also one of the backends, as on Windows.
         * <p>
         * Does NOT close the scheduler or the dispatcher: by default those are
         * zoxweb's process-wide pools, shared with the rest of no-sneak, and
         * shutting them down here would stop task processing for the whole
         * application.
         */
        @Override
        public void close() {
            for (HostDiscovery backend : perInterface) {
                if (backend != ping) {
                    backend.close();
                }
            }
            if (ping != null) {
                ping.close();
            }
        }
    }
}
