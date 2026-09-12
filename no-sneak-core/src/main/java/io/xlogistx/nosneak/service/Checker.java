package io.xlogistx.nosneak.service;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.SimpleProtoSession;
import io.xlogistx.http.EndpointsUtil;
import io.xlogistx.http.NIOHTTPServer;
import io.xlogistx.nosneak.ProbeChecker;
import io.xlogistx.nosneak.grade.Grade;
import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.nmap.ScanGate;
import io.xlogistx.nosneak.result.ProbeResult;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.api.APIException;
import org.zoxweb.shared.http.HTTPConst;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.http.URIScheme;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.protocol.ProtoSession;
import org.zoxweb.shared.task.CallableConsumerTask;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVLong;
import org.zoxweb.shared.util.ResourceManager;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * REST endpoint that runs the v2 probe engine against a {@code domain[:port]} and returns the
 * facts as JSON. The v2 replacement for the v1 {@code QDZChecker}: it drives the bundled probe
 * definitions (quick) or the {@code https-scan} deep-analysis definition (detailed) on the
 * shared {@link NIOSocket} of the running HTTP server.
 *
 * <h2>Fully asynchronous — the handler never blocks</h2>
 * A blocking wait here does not merely tie up a thread, it deadlocks the server: the HTTP server
 * builds its {@code NIOSocket} on {@code TaskUtil.defaultTaskProcessor()} and dispatches inbound
 * request data to that executor, so this method already runs on one of those workers — while the
 * probe sweep it would wait for needs the <em>same</em> pool ({@code Fanout.dispatch} publishes
 * every candidate start onto the socket's executor, and each probe's reads are re-dispatched
 * through it). Enough concurrent requests parked in {@code future.get} leave no worker able to
 * run the probes, so every request can only end in a timeout while the rest of the server stalls.
 * <p>
 * The async handshake with {@code NIOHTTPServer} has two halves, and both are required:
 * <ol>
 *   <li><b>Return {@link Boolean#FALSE}</b> so the server does not write a response — this
 *       endpoint owns it.</li>
 *   <li><b>Install a {@link ProtoSession} whose {@code canClose()} is false</b> until the
 *       response has been written. Without it the server treats the request as finished the
 *       moment this method returns: it calls {@code hph.reset()} and lets the keep-alive reaper
 *       close the connection, so a scan slower than the keep-alive timeout answers into a socket
 *       nobody is listening on. With it, both the reset and the close are skipped while the scan
 *       is in flight.</li>
 * </ol>
 * The response is written from the probe's completion callback, after which the session becomes
 * closeable and the connection is released.
 */
public class Checker extends PropertyContainer<NVGenericMap> {

    public static final LogWrapper log = new LogWrapper(Checker.class).setEnabled(false);

    private static final int TIMEOUT_SEC = 10;
    /** Backstop: if the sweep never calls back, answer anyway rather than leave the client hung. */
    private static final long RESPONSE_DEADLINE_SEC = TIMEOUT_SEC * 8L + 20L;

    /**
     * Pacing for one check: the candidate sweep opens every matching probe at once (17 bundled
     * definitions on a common port) and a deep probe adds its enumeration children, all against a
     * single host. Eight sockets in flight and 200 launches/s keep that an ordinary client load.
     */
    static final int MAX_IN_FLIGHT = 8;
    static final int MAX_PER_SEC = 200;

    /**
     * Checks answered so far — {@code total-scanned} in every response body, as v1 reported it.
     * Process-wide (the direct entry point counts too) and seeded from the server configuration's
     * {@code start-count-at} property when this class is configured as an HTTP server bean.
     */
    private static final AtomicLong SCAN_COUNT = new AtomicLong(1000);

    /** @return the number of checks answered so far (the value the next response will exceed by one) */
    public static long scanCount() {
        return SCAN_COUNT.get();
    }

    /** Reads {@code start-count-at} from the bean's configured properties; ignored when absent or {@code <= 0}. */
    @Override
    protected void refreshProperties() {
        try {
            NVGenericMap props = getProperties();
            if (props != null && props.getNV("start-count-at") != null) {
                long startCountingAt = props.getValueAsLong("start-count-at");
                if (startCountingAt > 0) {
                    SCAN_COUNT.set(startCountingAt);
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("start-count-at not applied: " + e);
        }
    }

    // ==================== Server-free entry point ====================

    /**
     * Run a check with <b>no HTTP server involved</b> and return the same body the REST endpoint
     * produces. This is the whole scan — target parsing, probe selection, the sweep, and the
     * facts+verdict response — with nothing but an {@link NIOSocket} behind it.
     * <p>
     * Blocking by design: it owns the {@code NIOSocket} it creates and closes it on the way out,
     * so it is safe to call from a {@code main}, a test, or any thread that is not a worker of the
     * pool the probes run on. (That last caveat is the whole reason the REST path is async — see
     * the class javadoc.)
     *
     * @param hostPort {@code "google.com:443"}, or {@code "google.com"} to default to 443
     */
    public static NVGenericMap checkQDZDirect(String hostPort) {
        return checkQDZDirect(hostPort, false);
    }

    /** @param detailed true = the single deep {@code https-scan} definition regardless of port. */
    public static NVGenericMap checkQDZDirect(String hostPort, boolean detailed) {
        IPAddress ip = target(hostPort);
        TargetGuard.Rejection rejected = TargetGuard.check(ip.getInetAddress());
        if (rejected != null) {
            throw new APIException(rejected.message(), rejected.status().CODE);
        }
        NIOSocket nio = null;
        try {
            nio = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
            ProbeChecker checker = checkerFor(nio, detailed);
            return response(checker.checkBlocking(ip.getInetAddress(), ip.getPort(), "tcp",
                    RESPONSE_DEADLINE_SEC * 1000L));
        } catch (Exception e) {
            return new NVGenericMap().build("error", "scan failed: " + e);
        } finally {
            SharedIOUtil.close(nio);
        }
    }

    /**
     * Parse {@code host[:port]} and default the port to 443. The private-target refusal is NOT
     * here any more: it needs the name resolved, which is blocking DNS work, so the REST path
     * does it on the socket's executor ({@link TargetGuard}) and the direct path does it
     * before opening a socket.
     */
    private static IPAddress target(String hostPort) {
        IPAddress ip = IPAddress.parse(hostPort);
        if (ip.getPort() == -1) {
            ip.setPort(URIScheme.HTTPS.getValue());
        }
        return ip;
    }

    /**
     * Refuses targets inside the operator's own network. The previous guard string-matched the
     * literal text against {@code 10.}, {@code 192.168.} and {@code 172.16-31.}, so
     * {@code 127.0.0.1}, {@code 169.254.169.254}, {@code [::1]}, a ULA, and any host name that
     * resolves inward all passed — and since the caller chooses the port, the endpoint was an
     * unauthenticated prober of whatever sits behind it. This one resolves the name and
     * classifies EVERY address it resolves to: one private address is enough to refuse, and a
     * name that does not resolve is refused as well rather than handed to the probe engine to
     * fail slowly.
     * <p>
     * Pure and DNS-free at the {@link #isPrivate(InetAddress)} level so the rules can be pinned
     * with literals ({@code CheckerPrivateIpTest}); {@link #check(String)} is the one place that
     * resolves.
     */
    public static final class TargetGuard {

        /** Why a target was refused, and the status the refusal carries. */
        public record Rejection(HTTPStatusCode status, String message) {}

        private TargetGuard() {}

        /**
         * Loopback, unspecified, link-local (169.254/16, fe80::/10), site-local
         * (10/8, 172.16/12, 192.168/16, fec0::/10), ULA (fc00::/7), shared address space
         * (100.64/10), the 0/8 block, and multicast. Everything else is a public host.
         */
        public static boolean isPrivate(InetAddress a) {
            if (a == null) {
                return true;
            }
            if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                    || a.isSiteLocalAddress() || a.isMulticastAddress()) {
                return true;
            }
            byte[] b = a.getAddress();
            if (b.length == 16) {
                return (b[0] & 0xFE) == 0xFC;                       // fc00::/7
            }
            if (b.length == 4) {
                int first = b[0] & 0xFF;
                if (first == 0) {
                    return true;                                    // 0.0.0.0/8
                }
                return first == 100 && (b[1] & 0xC0) == 0x40;       // 100.64.0.0/10
            }
            return false;
        }

        /**
         * Resolves {@code host} (a literal or a name) and refuses it if any address it resolves
         * to is private, or if it does not resolve at all. BLOCKING: DNS. Call it off the
         * request thread.
         *
         * @return null when the target may be scanned
         */
        public static Rejection check(String host) {
            String h = host == null ? "" : host.trim();
            if (h.isEmpty()) {
                return new Rejection(HTTPStatusCode.BAD_REQUEST, "No target given");
            }
            InetAddress[] all;
            try {
                all = InetAddress.getAllByName(h);
            } catch (UnknownHostException | SecurityException e) {
                return new Rejection(HTTPStatusCode.BAD_REQUEST, "Cannot resolve target: " + h);
            }
            for (InetAddress a : all) {
                if (isPrivate(a)) {
                    return new Rejection(HTTPStatusCode.UNAUTHORIZED,
                            "No scanning private or local targets: " + h + " resolves to "
                                    + a.getHostAddress());
                }
            }
            return null;
        }
    }

    private static ProbeChecker checkerFor(NIOSocket nio, boolean detailed) {
        List<ProbeDefinition> probes = detailed
                ? Collections.singletonList(ProbeDefinitionLoader.load("/probes/https-scan.json"))
                : ProbeDefinitionLoader.loadBundled();
        // Paced: without a gate a quick check opens every candidate's socket at once and a
        // detailed one adds up to MAX_ENUMERATION_CHILDREN handshakes, all at one host.
        ScanGate gate = new ScanGate(nio.getScheduler(), MAX_IN_FLIGHT, MAX_PER_SEC);
        return new ProbeChecker(nio, probes, gate)
                .timeoutInSec(TIMEOUT_SEC)
                .matchPorts(!detailed); // detailed = run the single https-scan def regardless of port
    }

    /** Standalone harness: {@code java …Checker google.com:443 [detailed]} — prints result + timing. */
    public static void main(String... args) {
        String hostPort = args.length > 0 ? args[0] : "google.com:443";
        boolean detailed = args.length > 1 && Boolean.parseBoolean(args[1]);
        long start = System.currentTimeMillis();
        NVGenericMap out = checkQDZDirect(hostPort, detailed);
        long elapsed = System.currentTimeMillis() - start;
        try {
            System.out.println(GSONUtil.toJSONGenericMap(out, true, true, false));
        } catch (Exception e) {
            System.out.println(out);
        }
        System.out.println("---- " + hostPort + (detailed ? " [detailed]" : "") + " took " + elapsed + " ms");
        System.exit(0); // one-shot: the shared pools are non-daemon
    }

    // ==================== REST endpoint ====================

    @EndPointProp(methods = {HTTPMethod.GET, HTTPMethod.POST},
            name = "check-qdz", uris = "/check-qdz/{domain}/{detailed}")
    public Object checkQDZ(@ParamProp(name = "domain") String domain,
                           @ParamProp(name = "detailed", optional = true) boolean detailed) {
        IPAddress ip = target(domain);
        if (log.isEnabled()) log.getLogger().info("checkQDZ ENTER domain=" + domain + " -> " + ip);
        NIOSocket nio = httpNIOSocket().getNIOSocket();
        ProbeChecker checker = checkerFor(nio, detailed);

        // Captured on the request thread: getProtocolHandler() reads the Shiro thread context,
        // which is unbound once this method returns. Always present here — this method only runs
        // as part of processing a request, and without a protocol handler there is no request.
        HTTPProtocolHandler hph = EndpointsUtil.SINGLETON.getProtocolHandler();

        // Hold the connection: not closeable, and not reset, until the response is written.
        // An authenticated request already carries a session (ShiroSession); an anonymous one
        // gets a SimpleProtoSession, which never touches the Shiro session store.
        Responder responder = new Responder(hph);
        ProtoSession<?, ?> protoSession = hph.getConnectionSession();
        if (protoSession == null) {
            protoSession = new SimpleProtoSession<String>();
            hph.setConnectionSession(protoSession);
        }
        protoSession.addCloseMonitor(responder);

        // The sweep has no deadline of its own, and a candidate that never calls back would
        // otherwise hold the connection open until the client gives up.
        nio.getScheduler().schedule(
                () -> responder.write(HTTPStatusCode.GATEWAY_TIMEOUT,
                        new NVGenericMap().build("error", "scan did not complete in time")),
                RESPONSE_DEADLINE_SEC, TimeUnit.SECONDS);

        // Resolving the name is blocking DNS work and the private-target rule needs the resolved
        // addresses, so both run on the socket's executor rather than on the request thread; the
        // response — a refusal or the scan result — is written through the same Responder.
        nio.getExecutor().execute(() -> {
            TargetGuard.Rejection rejected = TargetGuard.check(ip.getInetAddress());
            if (rejected != null) {
                responder.write(rejected.status(), new NVGenericMap().build("error", rejected.message()));
                return;
            }
            checker.check(ip.getInetAddress(), ip.getPort(), "tcp",
                    new CallableConsumerTask<ProbeResult>()
                            .setConsumer(r -> responder.write(HTTPStatusCode.OK, response(r)))
                            .setExceptionCallback(t -> responder.write(HTTPStatusCode.INTERNAL_SERVER_ERROR,
                                    new NVGenericMap().build("error", "scan failed"))));
        });

        return Boolean.FALSE; // we own the response; the server must not write one
    }

    /**
     * The facts, plus the derived verdict so a consumer reads one authoritative trust answer, and
     * the running {@code total-scanned} counter (incremented atomically per answered check).
     */
    private static NVGenericMap response(ProbeResult result) {
        NVGenericMap out = result.toNVGenericMap();
        if (result.getTlsState() != ProbeResult.TlsState.NONE) {
            out.add(Grade.of(result).toNVGenericMap());
        }
        out.add(new NVLong("total-scanned", SCAN_COUNT.incrementAndGet()));
        return out;
    }

    /**
     * Writes the deferred response exactly once, from whichever thread finishes first — the probe
     * callback or the backstop deadline — then releases the connection.
     */
    private static final class Responder implements Supplier<Boolean> {
        private final HTTPProtocolHandler hph;
        private final AtomicBoolean finished = new AtomicBoolean(false);
        private final AtomicBoolean written = new AtomicBoolean(false);

        Responder(HTTPProtocolHandler hph) {
            this.hph = hph;
        }

        public Boolean get()
        {
            return finished.get();
        }

        void write(HTTPStatusCode status, NVGenericMap body) {
            if (!written.compareAndSet(false, true)) {
                if (log.isEnabled()) log.getLogger().info("response already written, ignoring " + status);
                return;
            }
            try {
                if (log.isEnabled()) {
                    log.getLogger().info("writing " + status + " closed=" + hph.isClosed()
                            + " os=" + hph.getOutputStream()
                            + " requestComplete=" + hph.isRequestComplete());
                }
                if (hph.isClosed() || hph.getOutputStream() == null) {
                    return; // client went away
                }
                // Serialized here rather than handed to buildResponse as an object, because the
                // framework's JSON path uses GSONUtil.toJSONDefault, which omits default values —
                // every `false` boolean and `0` int silently vanishes (`complete:false`, a chain
                // link's `time-valid:false`, a connection's `index:0`), making a failed scan
                // indistinguishable from a clean one. This renderer includes them.
                String json = GSONUtil.toJSONGenericMap(body, true, true, false);
                // The status/headers-only variant on purpose: the (contentType, result, ...)
                // overload routes anything with a JSON content type back through the serializer,
                // which would encode this already-rendered document as a JSON *string*.
                HTTPMessageConfigInterface hmci = hph.buildResponse(status,
                        HTTPConst.CommonHeader.NO_CACHE_CONTROL);
                hmci.setContentType(HTTPConst.CommonHeader.CONTENT_TYPE_JSON_UTF8.getValue());
                hmci.setContent(json);
                HTTPUtil.writeHTTPResponse(hph.getResponseStream(), hmci, hph.getOutputStream());
                if (log.isEnabled()) log.getLogger().info("response written, " + json.length() + " bytes");
            } catch (Exception e) {
                if (log.isEnabled()) {
                    log.getLogger().info("failed writing check-qdz response: " + e);
                    e.printStackTrace();
                }
            } finally {
                // Released in this order: the session may only be closed once it is closeable.
                finished.set(true);
                hph.expire();
                SharedIOUtil.close(hph);
            }
        }
    }

    private org.zoxweb.server.http.HTTPNIOSocket httpNIOSocket() {
        NIOHTTPServer server = ResourceManager.lookupResource(ResourceManager.Resource.HTTP_SERVER);
        return server.getHTTPNIOSocket();
    }
}
