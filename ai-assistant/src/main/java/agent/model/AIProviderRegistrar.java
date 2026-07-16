package agent.model;

import agent.AIProvider;
import org.zoxweb.shared.util.RegistrarMapDefault;

/**
 *
 */
public class AIProviderRegistrar extends RegistrarMapDefault<String, AIProvider> {
    public AIProviderRegistrar() {
        super(k -> k, AIProvider::getName);
    }
}
