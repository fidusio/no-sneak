package io.xlogistx.nosneak.v2.data;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;

public class ReportContent extends PropertyDAO {

    public enum Param
            implements GetNVConfig {
        CONTENT(NVConfigManager.createNVConfig("content", "The content of the report", "Content", false, true, String.class));
        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }


    public static final NVConfigEntity NVC_REPORT_CONTENT = new NVConfigEntityPortable("report_content",
            null,
            "ReportContent",
            true,
            false,
            false,
            false,
            ReportContent.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            PropertyDAO.NVC_PROPERTY_DAO);

    public ReportContent() {
        super(NVC_REPORT_CONTENT);
    }

    public String getContent() {
        return lookupValue(Param.CONTENT);
    }

    public void setContent(String content) {
        setValue(Param.CONTENT, content);
    }
}
