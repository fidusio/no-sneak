package io.xlogistx.nosneak.v2.runtime;

/**
 * Admission control for sockets the probe engine opens: the same two calls the nmap
 * {@code ScanGate} exposes, expressed as an interface so the engine can be paced without
 * depending on the nmap package.
 * <p>
 * {@link #submit} queues a launch and runs it when a slot is free — possibly at once, on the
 * calling thread, possibly later on whichever thread frees a slot. {@link #release} must be
 * called <b>exactly once per launch that ran</b>. Nothing here may block: a gate that has no free
 * slot keeps the launch and returns.
 */
public interface ConnectionGate {

    void submit(Runnable launch);

    /**
     * Runs {@code launch} at once and counts it, even when the cap is full. For a socket that a
     * launched unit opens <em>for itself</em> — a deep TLS probe's version and cipher children —
     * and could not otherwise obtain while it holds its own slot: with a cap of two and two deep
     * candidates, every child would wait for a slot the parents never give back, and both probes
     * would time out having learned nothing. The cap is therefore soft for a unit's own children
     * and hard for everything else: while the children are counted, no <em>new</em> unit is
     * admitted until they finish. Nothing waits either way.
     */
    void submitNow(Runnable launch);

    void release();

    /** A gate with no limits: every launch runs at once and release is a no-op. */
    ConnectionGate UNLIMITED = new ConnectionGate() {
        @Override
        public void submit(Runnable launch) {
            launch.run();
        }

        @Override
        public void submitNow(Runnable launch) {
            launch.run();
        }

        @Override
        public void release() {
            // nothing was counted
        }
    };
}
