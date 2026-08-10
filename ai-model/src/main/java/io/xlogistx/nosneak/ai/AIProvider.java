package io.xlogistx.nosneak.ai;

import io.xlogistx.api.ai.AIAPI;
import io.xlogistx.nosneak.ai.model.AIRequest;
import io.xlogistx.nosneak.ai.model.AIResponse;
import org.zoxweb.server.io.UByteArrayInputStream;
import org.zoxweb.shared.security.APIKey;
import org.zoxweb.shared.task.ConsumerCallback;
import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.NVGenericMap;


/**
 * Main interface to implement for each type of provider (Claude, open AI, etc.).
 * Holds reference to the AI models under the provider that the user has access to,
 * the api key to access the provider, and a way to send and receive api calls to an
 * AI.
 */
public interface AIProvider extends GetName, GetDescription {


    AIModelCatalog getModelCatalog() throws AIException;

    void setAPIKey(APIKey<String> key);

    APIKey<String> getAPIKey();

    void setHTTPAPICaller(AIAPI APICaller);

    AIAPI getHTTPAPICaller();

    AIResponse send(AIRequest req, String skill) throws AIException;

    void asyncSend(AIRequest req, String skill, ConsumerCallback<NVGenericMap> callback) throws AIException;

    void asyncImageSend(AIRequest req, String skill, ConsumerCallback<NVGenericMap> callback, UByteArrayInputStream... images) throws AIException;

    String getID();
}
