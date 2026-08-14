package io.xlogistx.nosneak.ai;

import io.xlogistx.nosneak.ai.model.AIRequest;


/**
 * Runs one request through several providers so their answers can be compared.
 * <p>
 * <b>Designed, not built, and currently deprioritized</b> — there is no implementation, and the
 * assistant sends through a single provider. The interface is kept because the shape is still the
 * intended direction, but do not build against it expecting support.
 * <p>
 * Two shape problems to solve before implementing:
 * <ul>
 *   <li>{@link AICallbackCollection} returns flat lists with no provider key, so a caller cannot
 *       tell which answer came from which provider.</li>
 *   <li>One {@link AIRequest} carries one {@code model}, but each provider needs its own model id
 *       — so either the request is cloned per provider or a mapping has to be resolved here.</li>
 * </ul>
 * Note also that this has no {@code skill} parameter, unlike {@link AIProvider}'s send methods.
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
