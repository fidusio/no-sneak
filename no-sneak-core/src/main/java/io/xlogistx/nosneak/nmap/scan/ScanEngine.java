package io.xlogistx.nosneak.nmap.scan;

import io.xlogistx.nosneak.nmap.config.NMapConfig;
import io.xlogistx.nosneak.nmap.util.PortResult;
import io.xlogistx.nosneak.nmap.util.ScanCache;
import io.xlogistx.nosneak.nmap.util.ScanResult;
import io.xlogistx.nosneak.nmap.util.ScanType;
import org.zoxweb.server.net.NIOSocket;

import java.io.Closeable;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

/**
 * Interface for scan engine implementations.
 * Each scan type (TCP Connect, UDP, SYN, etc.) implements this interface.
 */
public interface ScanEngine extends Closeable {

    /**
     * Get the scan type this engine implements
     */
    ScanType getScanType();

    /**
     * Get a description of this engine
     */
    String getDescription();

    /**
     * Check if this engine is available on the current system.
     * Some engines (like SYN scan) may require raw sockets or special privileges.
     */
    boolean isAvailable();

    /**
     * Initialize the engine with an NIOSocket.
     * This is called before scanning begins.
     *
     * @param executorService the NIO socket to use for scanning
     * @param config the scan configuration
     */
    void init(ExecutorService executorService, NMapConfig config);

    /**
     * Scan a single port on a host.
     *
     * @param host the target host
     * @param port the port to scan
     * @return a future that completes with the port result
     */
    CompletableFuture<PortResult> scanPort(String host, int port);


//    void asyncScanPort(String host, int port);
//    void asyncScanHost(String host, List<Integer> ports);

//    void asyncScanPort(String host, int port);

    /**
     * Scan multiple ports on a host.
     *
     * @param host the target host
     * @param ports the ports to scan
     * @return a future that completes with the full scan result
     */
    CompletableFuture<ScanResult> scanHost(String host, List<Integer> ports);

    /**
     * Stop any in-progress scans and release resources.
     */
    void stop();

    /**
     * Get the number of scans currently in progress
     */
    int getActiveScans();

    /**
     * Check if this engine requires elevated privileges (root/admin)
     */
    default boolean requiresPrivileges() {
        return getScanType().requiresRawSockets();
    }

    /**
     * Get the protocol used by this engine
     */
    default String getProtocol() {
        return getScanType().getProtocol();
    }

    /**
     * Close the engine and release all resources
     */
    @Override
    void close();

    ExecutorService getExecutor();

    /**
     * Set the NIOSocket for engines that use NIO callback-based scanning.
     * This allows engines to use the shared NIOSocket event loop instead of
     * creating per-port Selectors.
     *
     * @param nioSocket the shared NIOSocket instance
     */
    default void setNIOSocket(NIOSocket nioSocket) {
        // Default no-op for engines that don't need NIOSocket
    }

    /**
     * Set the central ScanCache so this engine's maps are tracked for bulk reset.
     *
     * @param scanCache the shared ScanCache instance
     */
    default void setScanCache(ScanCache scanCache) {
        // Default no-op for engines that don't use maps
    }
}
