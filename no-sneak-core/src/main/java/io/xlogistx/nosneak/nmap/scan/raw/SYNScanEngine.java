package io.xlogistx.nosneak.nmap.scan.raw;

import io.xlogistx.nosneak.nmap.util.ScanType;

/**
 * TCP SYN (half-open) scan engine.
 * Delegates to nmap -sS which requires root/admin privileges.
 */
public class SYNScanEngine extends RawScanEngine {

    @Override
    public ScanType getScanType() {
        return ScanType.SYN;
    }

    @Override
    public String getDescription() {
        return "TCP SYN Scan - Half-open scanning (requires privileges)";
    }
}
