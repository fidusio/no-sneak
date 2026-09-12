package io.xlogistx.nosneak.nmap;

import io.xlogistx.common.dns.DNSRegistrar;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.ResolverConfig;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.DataPacket;
import org.zoxweb.server.net.common.UDPSessionCallback;
import org.zoxweb.server.net.ssl.SSLConfigInt;
import org.zoxweb.shared.io.SharedIOUtil;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * One non-blocking reverse lookup (PTR) for one address, on its own ephemeral datagram socket
 * connected to the resolver. Reports exactly once, fully event-driven: the query goes out in
 * {@link #connected}, the answer arrives through the selector, and the deadline is a task on
 * the injected scheduler. Nothing here calls {@code InetAddress.getHostName()} — that blocks a
 * pool thread for the whole resolver timeout, which is the one thing the scan pipeline must
 * never do.
 * <p>
 * The wire format is dnsjava's: {@link ReverseMap#fromAddress} builds the {@code in-addr.arpa}
 * / {@code ip6.arpa} name, {@link Message#newQuery} the query (random ID, recursion desired),
 * and {@link #parse} reads the reply. A reply whose ID is not ours is ignored and the wait
 * continues; {@code NXDOMAIN}, an answer without a PTR, a malformed reply, an ICMP error and
 * the deadline all complete with a null hostname and a reason naming which.
 */
public class ReverseDnsCallback extends UDPSessionCallback {

    public static final LogWrapper log = new LogWrapper(ReverseDnsCallback.class).setEnabled(false);

    /** Default PTR deadline; a resolver that has not answered in this long is not going to. */
    public static final long DEFAULT_TIMEOUT_MS = 2_000;
    public static final int DNS_PORT = 53;

    /** What one lookup found. {@code hostname} is null unless a PTR answered; {@code reason} says why. */
    public record Result(String hostname, String reason) { }

    private final ScheduledExecutorService scheduler;
    private final InetSocketAddress server;
    private final Message query;
    private final long timeoutMs;
    private final Consumer<Result> onResult;
    private final AtomicBoolean done = new AtomicBoolean(false);
    private volatile ScheduledFuture<?> deadline;

    /**
     * @param scheduler arms the deadline — injected, so the lookup times out on the same pools
     *                  its {@code NIOSocket} was built with
     * @param target    the address to reverse-resolve
     * @param server    the resolver to ask; see {@link #resolverAddress}
     * @param timeoutMs how long to wait for the reply
     */
    public ReverseDnsCallback(ScheduledExecutorService scheduler, InetAddress target,
                              InetSocketAddress server, long timeoutMs, Consumer<Result> onResult) {
        super(null, 0, 4096); // executor null: the selector thread hands us the key directly
        this.scheduler = scheduler;
        this.server = server;
        this.timeoutMs = timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;
        this.onResult = onResult;
        this.query = Message.newQuery(Record.newRecord(ReverseMap.fromAddress(target), Type.PTR, DClass.IN));
    }

    /** The query's transaction ID; a reply must carry it to count. */
    public int queryId() {
        return query.getHeader().getID();
    }

    /** The query as it goes on the wire (visible for tests). */
    public byte[] queryWire() {
        return query.toWire();
    }

    /**
     * The kickoff {@code NIOSocket} guarantees before any read dispatch: connect the channel to
     * the resolver, send the query, arm the deadline. A failure here propagates so the
     * registration is torn down; the caller completes the unit.
     */
    @Override
    public int connected(SelectionKey key) {
        int ops = super.connected(key);
        try {
            DatagramChannel ch = getChannel();
            ch.connect(server);
            synchronized (this) {
                ch.write(ByteBuffer.wrap(query.toWire()));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        arm();
        return ops;
    }

    /** Arms the deadline. Package-private for the test. */
    void arm() {
        deadline = scheduler.schedule(this::expire, timeoutMs, TimeUnit.MILLISECONDS);
    }

    /** The resolver never answered. */
    void expire() {
        finish(null, "timeout");
    }

    /** The scan was cancelled: nothing learned, say so, exactly once. */
    public void abort() {
        finish(null, "cancelled");
    }

    /** Read dispatch from the selector: drain what arrived and parse it. */
    @Override
    public void accept(SelectionKey key) {
        DatagramChannel ch = (DatagramChannel) key.channel();
        ByteBuffer buf = ByteBuffer.allocate(getBufferSize());
        try {
            SocketAddress from = ch.receive(buf);
            if (from != null) {
                buf.flip();
                byte[] bytes = new byte[buf.remaining()];
                buf.get(bytes);
                onDatagram(bytes);
            }
        } catch (Throwable t) {
            onError(t);
        }
    }

    /** Not used: {@link #accept(SelectionKey)} reads the channel itself so it can see an ICMP error. */
    @Override
    public void accept(DataPacket<?> dataPacket) {
        if (dataPacket == null) {
            return;
        }
        ByteBuffer buf = dataPacket.getIOBuffers().getInBuffer();
        byte[] bytes = new byte[buf == null ? 0 : buf.remaining()];
        if (buf != null) {
            buf.get(bytes);
        }
        onDatagram(bytes);
    }

    @Override
    public void exception(Throwable e) {
        onError(e);
    }

    @Override
    public void sslHandshakeSuccessful(SSLConfigInt config) {
        // not applicable to UDP
    }

    /** A datagram came back. A reply that is not ours (wrong ID) is ignored. Package-private for the test. */
    void onDatagram(byte[] wire) {
        Result r = parse(wire, queryId());
        if (r != null) {
            finish(r.hostname(), r.reason());
        }
    }

    /** An error on the channel: an ICMP message, or a dead socket. Package-private for the test. */
    void onError(Throwable t) {
        if (t instanceof UncheckedIOException u && u.getCause() != null) {
            t = u.getCause();
        }
        if (t instanceof PortUnreachableException) {
            finish(null, "port-unreach");
            return;
        }
        finish(null, "error:" + (t == null ? "unknown" : t.getClass().getSimpleName()));
    }

    /**
     * Reads a DNS reply. Pure.
     *
     * @return the PTR target (final dot dropped) with reason {@code ptr}; a null hostname with
     *         reason {@code nxdomain}, {@code rcode:<name>}, {@code no-answer} or
     *         {@code bad-reply}; or {@code null} when the reply is not an answer to
     *         {@code expectedId} and should be ignored
     */
    static Result parse(byte[] wire, int expectedId) {
        Message m;
        try {
            m = new Message(wire);
        } catch (Exception e) {
            return new Result(null, "bad-reply");
        }
        if (m.getHeader().getID() != expectedId || !m.getHeader().getFlag(Flags.QR)) {
            return null;
        }
        int rcode = m.getRcode();
        if (rcode == Rcode.NXDOMAIN) {
            return new Result(null, "nxdomain");
        }
        if (rcode != Rcode.NOERROR) {
            return new Result(null, "rcode:" + Rcode.string(rcode));
        }
        for (Record r : m.getSection(Section.ANSWER)) {
            if (r instanceof PTRRecord ptr) {
                String name = ptr.getTarget().toString(true);
                if (!name.isEmpty()) {
                    return new Result(name, "ptr");
                }
            }
        }
        return new Result(null, "no-answer");
    }

    /**
     * The resolver the PTR queries go to: {@code configured} when it is an IP literal (a
     * hostname here would itself need a lookup, which is refused with a warning), else the
     * system resolver's first entry, else {@link DNSRegistrar#DEFAULT_RESOLVER}. Never resolves
     * a name and never throws.
     *
     * @param warnings receives a note when {@code configured} was set but unusable; may be null
     */
    public static InetSocketAddress resolverAddress(String configured, List<String> warnings) {
        if (configured != null && !configured.isBlank()) {
            String c = configured.trim();
            if (NMapScanner.isIpLiteral(c)) {
                return literal(c);
            }
            if (warnings != null) {
                warnings.add("--dns-servers '" + c + "' is not an IP literal; using the system resolver");
            }
        }
        try {
            List<InetSocketAddress> servers = ResolverConfig.getCurrentConfig().servers();
            if (servers != null && !servers.isEmpty() && servers.get(0) != null) {
                return servers.get(0);
            }
        } catch (Throwable ignored) {
            // no readable system configuration: fall through to the public resolver
        }
        return literal(DNSRegistrar.DEFAULT_RESOLVER);
    }

    private static InetSocketAddress literal(String ip) {
        try {
            return new InetSocketAddress(InetAddress.getByName(ip), DNS_PORT); // literal: no lookup
        } catch (Exception e) {
            return InetSocketAddress.createUnresolved(ip, DNS_PORT);
        }
    }

    private void finish(String hostname, String reason) {
        if (!done.compareAndSet(false, true)) {
            return;
        }
        ScheduledFuture<?> d = deadline;
        deadline = null;
        if (d != null) {
            try { d.cancel(false); } catch (Exception ignored) { }
        }
        try { SharedIOUtil.close(this); } catch (Exception ignored) { }
        try { onResult.accept(new Result(hostname, reason)); } catch (Exception ignored) { }
    }
}
