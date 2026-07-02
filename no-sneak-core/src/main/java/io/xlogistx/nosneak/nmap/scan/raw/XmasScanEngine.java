package io.xlogistx.nosneak.nmap.scan.raw;

import io.xlogistx.nosneak.nmap.util.ScanType;

/**
 * TCP Xmas scan engine.
 * Delegates to nmap -sX which requires raw sockets.
 */
public class XmasScanEngine extends RawScanEngine {

    @Override
    public ScanType getScanType() {
        return ScanType.XMAS;
    }

    @Override
    public String getDescription() {
        return "TCP Xmas Scan - Sets the FIN, PSH, and URG flags";
    }
}
