package io.xlogistx.nosneak.ai;

import org.zoxweb.shared.security.APIKey;

import java.util.List;


/**
 * Interface that receives api keys from a source
 */
public interface AICredentialSource {

    List<APIKey<String>> APIKeys();

}
