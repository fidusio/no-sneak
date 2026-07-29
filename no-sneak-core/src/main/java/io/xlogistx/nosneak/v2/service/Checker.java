package io.xlogistx.nosneak.v2.service;

import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.http.EndpointsUtil;
import io.xlogistx.http.NIOHTTPServer;
import io.xlogistx.nosneak.v2.ProbeChecker;
import io.xlogistx.nosneak.v2.grade.Grade;
import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.v2.result.ProbeResult;
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
import org.zoxweb.shared.util.ResourceManager;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

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
public class Checker {

    public static final LogWrapper log = new LogWrapper(Checker.class).setEnabled(false);

    private static final int TIMEOUT_SEC = 10;
    /** Backstop: if the sweep never calls back, answer anyway rather than leave the client hung. */
    private static final long RESPONSE_DEADLINE_SEC = TIMEOUT_SEC * 8L + 20L;

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

    /** Parse {@code host[:port]}, default port 443, and refuse private targets. */
    private static IPAddress target(String hostPort) {
        IPAddress ip = IPAddress.parse(hostPort);
        if (ip.isPrivateIP()) {
            throw new APIException("No scanning private IPs: " + ip, HTTPStatusCode.UNAUTHORIZED.CODE);
        }
        if (ip.getPort() == -1) {
            ip.setPort(URIScheme.HTTPS.getValue());
        }
        return ip;
    }

    private static ProbeChecker checkerFor(NIOSocket nio, boolean detailed) {
        List<ProbeDefinition> probes = detailed
                ? Collections.singletonList(ProbeDefinitionLoader.load("/v2/probes/https-scan.json"))
                : ProbeDefinitionLoader.loadBundled();
        return new ProbeChecker(nio, probes)
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
        ScanSession session = new ScanSession();
        hph.setConnectionSession(session);
        Responder responder = new Responder(hph, session);

        // The sweep has no deadline of its own, and a candidate that never calls back would
        // otherwise hold the connection open until the client gives up.
        nio.getScheduler().schedule(
                () -> responder.write(HTTPStatusCode.GATEWAY_TIMEOUT,
                        new NVGenericMap().build("error", "scan did not complete in time")),
                RESPONSE_DEADLINE_SEC, TimeUnit.SECONDS);

        checker.check(ip.getInetAddress(), ip.getPort(), "tcp",
                new CallableConsumerTask<ProbeResult>()
                        .setConsumer(r -> responder.write(HTTPStatusCode.OK, response(r)))
                        .setExceptionCallback(t -> responder.write(HTTPStatusCode.INTERNAL_SERVER_ERROR,
                                new NVGenericMap().build("error", "scan failed"))));

        return Boolean.FALSE; // we own the response; the server must not write one
    }

    /** The facts, plus the derived verdict so a consumer reads one authoritative trust answer. */
    private static NVGenericMap response(ProbeResult result) {
        NVGenericMap out = result.toNVGenericMap();
        if (result.getTlsState() != ProbeResult.TlsState.NONE) {
            out.add(Grade.of(result).toNVGenericMap());
        }
        return out;
    }

    /**
     * Keeps the HTTP connection alive while the scan runs. {@code canClose()} stays false until
     * the response has been written, which is what stops {@code NIOHTTPServer} from resetting the
     * protocol handler and closing the socket as soon as the endpoint method returns.
     */
    private static final class ScanSession implements ProtoSession<Object, String> {
        private final NVGenericMap properties = new NVGenericMap("properties");
        private final Set<AutoCloseable> autoCloseables = new LinkedHashSet<>();
        private final AtomicBoolean responded = new AtomicBoolean(false);
        private final AtomicBoolean closed = new AtomicBoolean(false);

        void responded() {
            responded.set(true);
        }

        @Override
        public Object getSession() {
            return this;
        }

        @Override
        public boolean canClose() {
            return responded.get();
        }

        @Override
        public Set<AutoCloseable> getAutoCloseables() {
            return autoCloseables;
        }

        @Override
        public boolean attach() {
            return true;
        }

        @Override
        public boolean detach() {
            return true;
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                // setConnectionSession registered the protocol handler here, so this releases
                // the connection and its buffers.
                SharedIOUtil.close(autoCloseables.toArray(new AutoCloseable[0]));
            }
        }

        @Override
        public boolean isClosed() {
            return closed.get();
        }

        @Override
        public String getSubjectID() {
            return null;
        }

        @Override
        public NVGenericMap getProperties() {
            return properties;
        }
    }

    /**
     * Writes the deferred response exactly once, from whichever thread finishes first — the probe
     * callback or the backstop deadline — then releases the connection.
     */
    private static final class Responder {
        private final HTTPProtocolHandler hph;
        private final ScanSession session;
        private final AtomicBoolean written = new AtomicBoolean(false);

        Responder(HTTPProtocolHandler hph, ScanSession session) {
            this.hph = hph;
            this.session = session;
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
                session.responded();
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
