package io.xlogistx.nosneak.nmap.scan.raw;

import io.xlogistx.nosneak.nmap.util.ScanType;

/**
 * TCP FIN scan engine.
 * Delegates to nmap -sF which requires raw sockets.
 */
public class FINScanEngine extends RawScanEngine {

    @Override
    public ScanType getScanType() {
        return ScanType.FIN;
    }

    @Override
    public String getDescription() {
        return "TCP FIN Scan - Sets just the TCP FIN bit";
    }
}
