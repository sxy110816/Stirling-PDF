package stirling.software.SPDF.model;

import java.util.Collection;

public interface ProviderInterface {

    Collection<String> getScopes();

    void setScopes(String scopes);

    String getUseAsUsername();

    void setUseAsUsername(String useAsUsername);

    String getIssuer();

    void setIssuer(String issuer);

    String getClientSecret();

    void setClientSecret(String clientSecret);

    String getClientId();

    void setClientId(String clientId);
}
