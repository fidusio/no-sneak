package io.xlogistx.nosneak.nmap.scan.raw;

import io.xlogistx.nosneak.nmap.util.ScanType;

/**
 * TCP NULL scan engine.
 * Delegates to nmap -sN which requires raw sockets.
 */
public class NullScanEngine extends RawScanEngine {

    @Override
    public ScanType getScanType() {
        return ScanType.NULL;
    }

    @Override
    public String getDescription() {
        return "TCP NULL Scan - Does not set any bits (TCP flag header is 0)";
    }
}
