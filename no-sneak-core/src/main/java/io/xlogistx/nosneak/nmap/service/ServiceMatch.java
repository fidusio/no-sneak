package io.xlogistx.nosneak.nmap.service;

/**
 * Represents a matched service on a port.
 */
public class ServiceMatch {

    private final String serviceName;     // e.g., "http", "ssh", "ftp"
    private final String product;         // e.g., "Apache httpd", "OpenSSH"
    private final String version;         // e.g., "2.4.41", "8.2p1"
    private final String extraInfo;       // e.g., "Ubuntu", "protocol 2.0"
    private final String osType;          // e.g., "Linux", "Windows"
    private final String deviceType;      // e.g., "general purpose", "router"
    private final int confidence;         // 0-100 confidence level
    private final String method;          // How detected: "probed", "banner", "table"
    private final String cpe;             // CPE identifier if available

    private ServiceMatch(Builder builder) {
        this.serviceName = builder.serviceName;
        this.product = builder.product;
        this.version = builder.version;
        this.extraInfo = builder.extraInfo;
        this.osType = builder.osType;
        this.deviceType = builder.deviceType;
        this.confidence = builder.confidence;
        this.method = builder.method;
        this.cpe = builder.cpe;
    }

    // Getters
    public String getServiceName() { return serviceName; }
    public String getProduct() { return product; }
    public String getVersion() { return version; }
    public String getExtraInfo() { return extraInfo; }
    public String getOsType() { return osType; }
    public String getDeviceType() { return deviceType; }
    public int getConfidence() { return confidence; }
    public String getMethod() { return method; }
    public String getCpe() { return cpe; }

    /**
     * Check if service has version information
     */
    public boolean hasVersion() {
        return version != null && !version.isEmpty();
    }

    /**
     * Check if service has product name
     */
    public boolean hasProduct() {
        return product != null && !product.isEmpty();
    }

    /**
     * Get full service string (name + product + version)
     */
    public String getFullServiceString() {
        StringBuilder sb = new StringBuilder();
        sb.append(serviceName);
        if (product != null) {
            sb.append(" (").append(product);
            if (version != null) {
                sb.append(" ").append(version);
            }
            sb.append(")");
        }
        return sb.toString();
    }

    /**
     * Create a simple service match with just name
     */
    public static ServiceMatch simple(String serviceName) {
        return builder(serviceName).build();
    }

    /**
     * Create a service match from well-known port
     */
    public static ServiceMatch fromPort(int port, String protocol) {
        String service = getWellKnownService(port, protocol);
        if (service != null) {
            return builder(service).method("table").confidence(50).build();
        }
        return null;
    }

    /**
     * Get well-known service name for port
     */
    public static String getWellKnownService(int port, String protocol) {
        if ("tcp".equals(protocol)) {
            switch (port) {
                case 20: return "ftp-data";
                case 21: return "ftp";
                case 22: return "ssh";
                case 23: return "telnet";
                case 25: return "smtp";
                case 53: return "domain";
                case 80: return "http";
                case 110: return "pop3";
                case 111: return "rpcbind";
                case 135: return "msrpc";
                case 139: return "netbios-ssn";
                case 143: return "imap";
                case 443: return "https";
                case 445: return "microsoft-ds";
                case 465: return "smtps";
                case 587: return "submission";
                case 993: return "imaps";
                case 995: return "pop3s";
                case 1433: return "ms-sql-s";
                case 1521: return "oracle";
                case 3306: return "mysql";
                case 3389: return "ms-wbt-server";
                case 5432: return "postgresql";
                case 5900: return "vnc";
                case 6379: return "redis";
                case 8080: return "http-proxy";
                case 8443: return "https-alt";
                case 27017: return "mongodb";
                default: return null;
            }
        } else if ("udp".equals(protocol)) {
            switch (port) {
                case 53: return "domain";
                case 67: return "dhcps";
                case 68: return "dhcpc";
                case 69: return "tftp";
                case 123: return "ntp";
                case 137: return "netbios-ns";
                case 138: return "netbios-dgm";
                case 161: return "snmp";
                case 162: return "snmptrap";
                case 500: return "isakmp";
                case 514: return "syslog";
                case 520: return "route";
                case 1900: return "upnp";
                case 5353: return "mdns";
                default: return null;
            }
        }
        return null;
    }

    public static Builder builder(String serviceName) {
        return new Builder(serviceName);
    }

    public static class Builder {
        private final String serviceName;
        private String product;
        private String version;
        private String extraInfo;
        private String osType;
        private String deviceType;
        private int confidence = 100;
        private String method = "probed";
        private String cpe;

        public Builder(String serviceName) {
            this.serviceName = serviceName;
        }

        public Builder product(String product) {
            this.product = product;
            return this;
        }

        public Builder version(String version) {
            this.version = version;
            return this;
        }

        public Builder extraInfo(String info) {
            this.extraInfo = info;
            return this;
        }

        public Builder osType(String osType) {
            this.osType = osType;
            return this;
        }

        public Builder deviceType(String deviceType) {
            this.deviceType = deviceType;
            return this;
        }

        public Builder confidence(int confidence) {
            this.confidence = Math.max(0, Math.min(100, confidence));
            return this;
        }

        public Builder method(String method) {
            this.method = method;
            return this;
        }

        public Builder cpe(String cpe) {
            this.cpe = cpe;
            return this;
        }

        public ServiceMatch build() {
            return new ServiceMatch(this);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(serviceName);
        if (product != null) {
            sb.append(" ").append(product);
        }
        if (version != null) {
            sb.append(" ").append(version);
        }
        if (extraInfo != null) {
            sb.append(" (").append(extraInfo).append(")");
        }
        return sb.toString();
    }
}
