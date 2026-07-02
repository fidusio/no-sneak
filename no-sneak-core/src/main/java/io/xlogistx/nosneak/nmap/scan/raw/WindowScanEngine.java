package io.xlogistx.nosneak.nmap.scan.raw;

import io.xlogistx.nosneak.nmap.util.ScanType;

/**
 * TCP Window scan engine.
 * Delegates to nmap -sW which requires raw sockets.
 * Like ACK scan but can sometimes differentiate open from closed ports
 * based on TCP Window field values.
 */
public class WindowScanEngine extends RawScanEngine {

    @Override
    public ScanType getScanType() {
        return ScanType.WINDOW;
    }

    @Override
    public String getDescription() {
        return "TCP Window Scan - Like ACK scan, uses Window field to detect open ports";
    }
}
