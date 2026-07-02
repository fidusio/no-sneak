package io.xlogistx.nosneak.nmap.config;

/**
 * Timing templates matching nmap's -T0 through -T5 options.
 * Controls scan speed, parallelism, and timeout behavior.
 */
public enum TimingTemplate {
    T0("paranoid", 300_000, 1, 300, 5),      // 5 min delay between probes
    T1("sneaky", 15_000, 1, 15, 15),         // 15 sec delay
    T2("polite", 400, 10, 1, 10),            // 0.4 sec delay
    T3("normal", 0, 100, 0, 10),             // default - no artificial delay
    T4("aggressive", 0, 256, 0, 5),          // fast, more parallel
    T5("insane", 0, 512, 0, 2);              // very fast, max parallel

    private final String name;
    private final long minDelayMs;
    private final int maxParallelism;
    private final long probeDelayMs;
    private final int timeoutSec;

    TimingTemplate(String name, long minDelayMs, int maxParallelism, long probeDelayMs, int timeoutSec) {
        this.name = name;
        this.minDelayMs = minDelayMs;
        this.maxParallelism = maxParallelism;
        this.probeDelayMs = probeDelayMs;
        this.timeoutSec = timeoutSec;
    }

    public String getName() {
        return name;
    }

    public long getMinDelayMs() {
        return minDelayMs;
    }

    public int getMaxParallelism() {
        return maxParallelism;
    }

    public long getProbeDelayMs() {
        return probeDelayMs;
    }

    public int getTimeoutSec() {
        return timeoutSec;
    }

    /**
     * Parse timing template from string (e.g., "T3", "3", "normal")
     */
    public static TimingTemplate parse(String value) {
        if (value == null || value.isEmpty()) {
            return T3;
        }

        String upper = value.toUpperCase().trim();

        // Try direct enum match (T0, T1, etc.)
        for (TimingTemplate t : values()) {
            if (t.name().equals(upper)) {
                return t;
            }
        }

        // Try number only (0, 1, 2, etc.)
        if (upper.matches("\\d")) {
            return valueOf("T" + upper);
        }

        // Try name match (paranoid, sneaky, etc.)
        String lower = value.toLowerCase().trim();
        for (TimingTemplate t : values()) {
            if (t.name.equals(lower)) {
                return t;
            }
        }

        return T3; // default
    }

    @Override
    public String toString() {
        return name() + "(" + name + ")";
    }
}
