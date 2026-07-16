package agent;

import agent.model.AIRequest;


/**
 * Runs one request through multiple different providers.
 */
public interface AIRunner {

    /**
     *
     * @param req       the one request to send
     * @param providers list of providers to send the request to
     * @return an AICallbackCollection that collects the results
     */
    AICallbackCollection send(AIRequest req, AIProvider... providers);

}
