package io.xlogistx.nosneak.v2.service;

import io.xlogistx.http.NIOHTTPServer;
import io.xlogistx.nosneak.v2.ProbeChecker;
import io.xlogistx.nosneak.v2.grade.Grade;
import io.xlogistx.nosneak.v2.model.ProbeDefinition;
import io.xlogistx.nosneak.v2.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.v2.result.ProbeResult;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.api.APIException;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.http.URIScheme;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.ResourceManager;

import java.util.Collections;
import java.util.List;

/**
 * REST endpoint that runs the v2 probe engine against a {@code domain[:port]} and returns the
 * facts as JSON. The v2 replacement for the v1 {@code QDZChecker}: it drives the bundled probe
 * definitions (quick) or the {@code https-scan} deep-analysis definition (detailed) on the
 * shared {@link NIOSocket} of the running HTTP server, and uses a <b>bounded</b> wait rather
 * than v1's unbounded {@code future.join()}.
 */
public class Checker {

    @EndPointProp(methods = {HTTPMethod.GET, HTTPMethod.POST},
            name = "check-qdz", uris = "/check-qdz/{domain}/{detailed}")
    public NVGenericMap checkQDZ(@ParamProp(name = "domain") String domain,
                                 @ParamProp(name = "detailed", optional = true) boolean detailed) {
        IPAddress ip = IPAddress.parse(domain);
        if (ip.isPrivateIP()) {
            throw new APIException("No scanning private IPs: " + ip, HTTPStatusCode.UNAUTHORIZED.CODE);
        }
        if (ip.getPort() == -1) {
            ip.setPort(URIScheme.HTTPS.getValue());
        }

        NIOSocket nio = httpNIOSocket().getNIOSocket();
        List<ProbeDefinition> probes = detailed
                ? Collections.singletonList(ProbeDefinitionLoader.load("/v2/probes/https-scan.json"))
                : ProbeDefinitionLoader.loadBundled();

        int timeoutSec = 10;
        ProbeChecker checker = new ProbeChecker(nio, probes)
                .timeoutInSec(timeoutSec)
                .matchPorts(!detailed); // detailed = run the single https-scan def regardless of port

        long maxWaitMs = (timeoutSec * 8L + 20L) * 1000L; // bounded (not an unbounded join)
        ProbeResult result = checker.checkBlocking(ip.getInetAddress(), ip.getPort(), "tcp", maxWaitMs);
        NVGenericMap out = result.toNVGenericMap();
        if (result.getTlsState() != ProbeResult.TlsState.NONE) {
            // Merge the derived verdict (grade / pqc-readiness / trust-verdict / trust-reason)
            // so a consumer reads one authoritative trust answer instead of re-deriving it.
            out.add(Grade.of(result).toNVGenericMap());
        }
        return out;
    }

    private org.zoxweb.server.http.HTTPNIOSocket httpNIOSocket() {
        NIOHTTPServer server = ResourceManager.lookupResource(ResourceManager.Resource.HTTP_SERVER);
        return server.getHTTPNIOSocket();
    }
}
