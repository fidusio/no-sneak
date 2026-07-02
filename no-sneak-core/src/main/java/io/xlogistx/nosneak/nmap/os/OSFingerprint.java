package io.xlogistx.nosneak.nmap.os;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents an OS fingerprinting result.
 */
public class OSFingerprint {

    private final List<OSMatch> matches;
    private final int ttl;
    private final int windowSize;
    private final String tcpOptions;
    private final boolean dfSet;  // Don't Fragment flag

    private OSFingerprint(Builder builder) {
        this.matches = Collections.unmodifiableList(new ArrayList<>(builder.matches));
        this.ttl = builder.ttl;
        this.windowSize = builder.windowSize;
        this.tcpOptions = builder.tcpOptions;
        this.dfSet = builder.dfSet;
    }

    public List<OSMatch> getMatches() { return matches; }
    public int getTtl() { return ttl; }
    public int getWindowSize() { return windowSize; }
    public String getTcpOptions() { return tcpOptions; }
    public boolean isDfSet() { return dfSet; }

    /**
     * Get the best OS match (highest confidence)
     */
    public OSMatch getBestMatch() {
        if (matches.isEmpty()) return null;
        return matches.get(0);
    }

    /**
     * Check if any matches were found
     */
    public boolean hasMatches() {
        return !matches.isEmpty();
    }

    /**
     * Guess OS family from TTL
     */
    public static String guessOsFamilyFromTtl(int ttl) {
        if (ttl <= 64) {
            return "Linux/Unix";
        } else if (ttl <= 128) {
            return "Windows";
        } else if (ttl <= 255) {
            return "Network Device";
        }
        return "Unknown";
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private List<OSMatch> matches = new ArrayList<>();
        private int ttl = -1;
        private int windowSize = -1;
        private String tcpOptions;
        private boolean dfSet = false;

        public Builder addMatch(OSMatch match) {
            matches.add(match);
            return this;
        }

        public Builder addMatch(String osName, int accuracy) {
            matches.add(new OSMatch(osName, accuracy));
            return this;
        }

        public Builder ttl(int ttl) {
            this.ttl = ttl;
            return this;
        }

        public Builder windowSize(int size) {
            this.windowSize = size;
            return this;
        }

        public Builder tcpOptions(String options) {
            this.tcpOptions = options;
            return this;
        }

        public Builder dfSet(boolean df) {
            this.dfSet = df;
            return this;
        }

        public OSFingerprint build() {
            // Sort matches by accuracy (highest first)
            matches.sort((a, b) -> Integer.compare(b.getAccuracy(), a.getAccuracy()));
            return new OSFingerprint(this);
        }
    }

    /**
     * Represents a single OS match with confidence
     */
    public static class OSMatch {
        private final String osName;
        private final String osFamily;
        private final String osGen;     // Generation (e.g., "2.6.X" for Linux)
        private final int accuracy;     // 0-100
        private final String cpe;

        public OSMatch(String osName, int accuracy) {
            this(osName, null, null, accuracy, null);
        }

        public OSMatch(String osName, String osFamily, String osGen, int accuracy, String cpe) {
            this.osName = osName;
            this.osFamily = osFamily;
            this.osGen = osGen;
            this.accuracy = accuracy;
            this.cpe = cpe;
        }

        public String getOsName() { return osName; }
        public String getOsFamily() { return osFamily; }
        public String getOsGen() { return osGen; }
        public int getAccuracy() { return accuracy; }
        public String getCpe() { return cpe; }

        @Override
        public String toString() {
            return osName + " (" + accuracy + "%)";
        }
    }

    @Override
    public String toString() {
        if (matches.isEmpty()) {
            if (ttl > 0) {
                return "OS guess from TTL(" + ttl + "): " + guessOsFamilyFromTtl(ttl);
            }
            return "No OS matches";
        }
        return getBestMatch().toString();
    }
}
