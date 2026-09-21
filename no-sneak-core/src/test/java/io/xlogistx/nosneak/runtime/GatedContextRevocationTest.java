package io.xlogistx.nosneak.runtime;

import io.xlogistx.nosneak.model.ProbeDefinition;
import io.xlogistx.nosneak.model.ProbeDefinitionLoader;
import io.xlogistx.nosneak.nmap.ScanGate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskProcessor;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.net.IPAddress;

import java.util.concurrent.ScheduledThreadPoolExecutor;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * {@code revocation-check} needs an HTTP client, which {@link ProbeContext#httpNio()} builds
 * from the context's socket. The gated registry — every scanner and app probe — used to build
 * its contexts through the socket-less seam, so the check reported {@code UNKNOWN/none} on every
 * scan while the direct CLI reported {@code GOOD/crl} for the same host (2026-09-20). This pins
 * the two production constructors to a usable HTTP client and the seam to none.
 */
public class GatedContextRevocationTest {

    private TaskProcessor executor;
    private TaskSchedulerProcessor scheduler;
    private NIOSocket nio;
    private final ScheduledThreadPoolExecutor jdkScheduler = new ScheduledThreadPoolExecutor(1);

    @BeforeEach
    public void pools() throws Exception {
        executor = new TaskProcessor("gated-rev", 16, 2, Thread.NORM_PRIORITY, false);
        scheduler = new TaskSchedulerProcessor(executor);
        nio = new NIOSocket(executor, scheduler);
    }

    @AfterEach
    public void shutdown() {
        try { nio.close(); } catch (Exception ignored) { }
        try { scheduler.close(); } catch (Exception ignored) { }
        try { executor.close(); } catch (Exception ignored) { }
        jdkScheduler.shutdownNow();
    }

    private static ProbeDefinition httpsScan() {
        return ProbeDefinitionLoader.load("/probes/https-scan.json");
    }

    @Test
    public void aGatedProductionContextCanBuildItsHttpClient() {
        GatedProbeTransport.Registry registry = new GatedProbeTransport.Registry(new ScanGate(jdkScheduler, 8, 0));
        ProbeContext ctx = registry.create(nio, new IPAddress("example.invalid", 443), httpsScan(), 5, r -> { });
        assertNotNull(ctx.httpNio(), "the gated path must be able to run an active revocation check");
        assertSame(ctx.httpNio(), ctx.httpNio(), "built once, then reused");
    }

    @Test
    public void theUngatedProductionContextCanToo() {
        ProbeContext ctx = new ProbeContext(nio, new IPAddress("example.invalid", 443), httpsScan(), 5, r -> { });
        assertNotNull(ctx.httpNio());
    }

    @Test
    public void theScriptedSeamStaysOffTheNetwork() {
        GatedProbeTransport.Registry registry = new GatedProbeTransport.Registry(new ScanGate(jdkScheduler, 8, 0));
        ProbeContext ctx = registry.create(new ScriptedTransport(), jdkScheduler, Runnable::run,
                new IPAddress("example.invalid", 443), httpsScan(), 5, r -> { });
        assertNull(ctx.httpNio(), "a scripted probe reports revocation unknown rather than fetching anything");
    }
}
