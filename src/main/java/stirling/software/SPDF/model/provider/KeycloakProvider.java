package stirling.software.SPDF.model.provider;

import java.util.ArrayList;
import java.util.Collection;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class KeycloakProvider extends Provider {

    private static final String NAME = "keycloak";
    private static final String CLIENT_NAME = "Keycloak";

    public KeycloakProvider(
            String issuer, String clientId, String clientSecret, String useAsUsername) {
        super(
                issuer,
                NAME,
                CLIENT_NAME,
                clientId,
                clientSecret,
                new ArrayList<>(),
                useAsUsername,
                null,
                null,
                null);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getClientName() {
        return CLIENT_NAME;
    }

    @Override
    public Collection<String> getScopes() {
        var scopes = super.getScopes();

        if (scopes == null || scopes.isEmpty()) {
            scopes = new ArrayList<>();
            scopes.add("profile");
            scopes.add("email");
        }

        return scopes;
    }

    @Override
    public String toString() {
        return "Keycloak [issuer="
                + getIssuer()
                + ", clientId="
                + getClientId()
                + ", clientSecret="
                + (getClientSecret() != null && !getClientSecret().isBlank() ? "MASKED" : "NULL")
                + ", scopes="
                + getScopes()
                + ", useAsUsername="
                + getUseAsUsername()
                + "]";
    }
}
