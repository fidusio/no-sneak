package io.xlogistx.nosneak.data;

import org.zoxweb.shared.data.PropertyImpl;
import org.zoxweb.shared.util.*;

public class ProbeType extends PropertyImpl {

    public enum Param
            implements GetNVConfig {
        DEFINITION(NVConfigManager.createNVConfig("definition", "The gson definition of the probe", "Definition", false, true, String.class));
        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }


    public static final NVConfigEntity NVC_PROBE_TYPE = new NVConfigEntityPortable("probe_type",
            null,
            "ProbeType",
            true,
            false,
            false,
            false,
            ProbeType.class,
            SUS.extractNVConfigs(Param.values()),
            null,
            false,
            PropertyImpl.NVC_PROPERTY_IMPL);

    public ProbeType() {
        super(NVC_PROBE_TYPE);
    }

    @Override
    public void setName(String name) {
        name = SUS.trimOrNull(DataEncoder.StringLower.encode(name));
        SUS.checkIfNull("probe name can't be null or empty", name);
        super.setName(name);
    }


    public String getDefinition() {
        return lookupValue(Param.DEFINITION);
    }

    public void setDefinition(String probeDefinition) {
        setValue(Param.DEFINITION, probeDefinition);
    }
}
