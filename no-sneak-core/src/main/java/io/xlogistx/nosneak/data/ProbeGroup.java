package io.xlogistx.nosneak.data;

import org.zoxweb.shared.data.PropertyImpl;
import org.zoxweb.shared.util.*;

import java.util.ArrayList;
import java.util.List;

/**
 * A named set of probes a subject saves to tick in one go (2026-11-01). Mirrors
 * {@link ProbeContent}: the DAO base carries the name and the description, the one param here
 * is the member probes as a comma-separated list of <b>names</b> — not tick keys — resolved
 * against the bundled set and the subject's own probes whenever the group is used, exactly as a
 * stored report's {@code probes} property is resolved for <i>Scan again</i>. A group never
 * reaches the engine: ticking it ticks its probes, and the report records those probes.
 */
public class ProbeGroup extends PropertyImpl {

    public enum Param
            implements GetNVConfig {
        PROBES(NVConfigManager.createNVConfig("probes", "The member probes, names comma-separated", "Probes", false, true, String.class));
        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_PROBE_GROUP = new NVConfigEntityPortable("probe_group",
            null,
            "ProbeGroup",
            true,
            false,
            false,
            false,
            ProbeGroup.class,
            SUS.extractNVConfigs(Param.values()),
            null,
            false,
            PropertyImpl.NVC_PROPERTY_IMPL);

    public ProbeGroup() {
        super(NVC_PROBE_GROUP);
    }

    /** The member probe names, comma-separated, as stored. */
    public String getProbes() {
        return lookupValue(Param.PROBES);
    }

    public void setProbes(String csv) {
        setValue(Param.PROBES, csv);
    }

    /** The member names trimmed, blanks dropped, in stored order. Empty for a group with no probes. */
    public List<String> probeNames() {
        return parseNames(getProbes());
    }

    /** {@code "ssh, https-pqc,,"} → {@code [ssh, https-pqc]}; null or blank → empty. */
    public static List<String> parseNames(String csv) {
        List<String> out = new ArrayList<>();
        if (SUS.isEmpty(csv)) return out;
        for (String raw : csv.split(",")) {
            String name = raw.trim();
            if (SUS.trimOrNull(name) != null) out.add(name);
        }
        return out;
    }
}
