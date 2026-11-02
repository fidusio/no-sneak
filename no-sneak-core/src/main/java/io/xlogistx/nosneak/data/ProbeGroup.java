package io.xlogistx.nosneak.data;

import org.zoxweb.shared.data.PropertyImpl;
import org.zoxweb.shared.util.*;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A named set of probes a subject saves to tick in one go (2026-11-01). Mirrors
 * {@link ProbeContent}: the DAO base carries the name and the description, the one param here
 * is the member probes as an ordered set of <b>names</b> (an {@code NVStringSet}, stored as a
 * JSON column) — not tick keys — resolved against the bundled set and the subject's own probes
 * whenever the group is used, exactly as a stored report's {@code probes} property is resolved
 * for <i>Scan again</i>. A group never reaches the engine: ticking it ticks its probes, and the
 * report records those probes.
 */
public class ProbeGroup extends PropertyImpl {

    public enum Param
            implements GetNVConfig {
        PROBES(NVConfigManager.createNVConfig("probes", "The member probes, a set of names", "Probes", false, true, NVStringSet.class));
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

    /** The member probe names, in stored order; the live set, so a change to it is a change to the group. */
    public Set<String> getProbes() {
        return lookupValue(Param.PROBES);
    }

    /** Replaces the members with the names of a comma-separated list, trimmed, blanks dropped. */
    public void setProbes(String csv) {
        setValue(Param.PROBES, parseNames(csv));
    }

    /** Replaces the members with {@code probes}, in its iteration order; the same set is a no-op. */
    public void setProbes(Set<String> probes) {
        Set<String> probeValue = getProbes();
        if(probeValue != probes) {
            probeValue.clear();
            probeValue.addAll(probes);
        }
    }

    /** {@code "ssh, https-pqc,,"} → {@code [ssh, https-pqc]} in that order; null or blank → empty. */
    public static Set<String> parseNames(String csv) {
        Set<String> out = new LinkedHashSet<String>();
        if (SUS.isEmpty(csv)) return out;
        for (String raw : csv.split(",")) {
            String name = raw.trim();
            if (SUS.trimOrNull(name) != null) out.add(name);
        }
        return out;
    }
}
