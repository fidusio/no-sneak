package io.xlogistx.nosneak.ai.model;


import io.xlogistx.api.ai.AIAPI;
import io.xlogistx.api.ai.AIAPIBuilder;
import org.zoxweb.shared.util.ParamUtil;

import java.util.Arrays;

public class AIAPITest {

    static void main(String... args) {

        try {
            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            String aiToken = params.stringValue("ai-token");
            AIAPIBuilder.AIAPIType aiapiType = params.enumValue("ai-type", AIAPIBuilder.AIAPIType.values());

            AIAPI aiapi = AIAPIBuilder.createAIAPI(aiapiType, null, aiToken);
            String[] models = aiapi.availableModels();
            System.out.println(Arrays.toString(models) + "\n" + models.length);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
