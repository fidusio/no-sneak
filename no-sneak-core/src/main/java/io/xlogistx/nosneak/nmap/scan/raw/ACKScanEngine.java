package io.xlogistx.nosneak.nmap.scan.raw;

import io.xlogistx.nosneak.nmap.util.ScanType;

/**
 * TCP ACK scan engine.
 * Delegates to nmap -sA which requires raw sockets.
 * Used to map firewall rulesets and determine if ports are filtered.
 */
public class ACKScanEngine extends RawScanEngine {

    @Override
    public ScanType getScanType() {
        return ScanType.ACK;
    }

    @Override
    public String getDescription() {
        return "TCP ACK Scan - Map firewall rulesets";
    }
}
