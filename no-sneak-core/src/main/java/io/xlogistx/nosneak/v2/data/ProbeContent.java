package io.xlogistx.nosneak.v2.data;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

public class ProbeContent extends PropertyDAO {

    public enum Param
            implements GetNVConfig {
        CONTENT(NVConfigManager.createNVConfig("content", "The content of the probe", "Content", false, true, String.class));
        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }


    public static final NVConfigEntity NVC_PROBE_CONTENT = new NVConfigEntityPortable("probe_content",
            null,
            "ProbeContent",
            true,
            false,
            false,
            false,
            ProbeContent.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            PropertyDAO.NVC_PROPERTY_DAO);

    public ProbeContent() {
        super(NVC_PROBE_CONTENT);
    }


    public String getContent() {
        return lookupValue(Param.CONTENT);
    }

    public void setContent(String content) {
        setValue(Param.CONTENT, content);
    }
}
