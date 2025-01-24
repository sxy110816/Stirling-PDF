package stirling.software.SPDF.model.provider;

import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public abstract class Provider {

    private String issuer;
    private String name;
    private String clientName;
    private String clientId;
    private String clientSecret;
    private Collection<String> scopes;
    private String useAsUsername;

    public Provider(
            String issuer,
            String name,
            String clientName,
            String clientId,
            String clientSecret,
            Collection<String> scopes,
            String useAsUsername) {
        this.issuer = issuer;
        this.name = name;
        this.clientName = clientName;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scopes = scopes;
        this.useAsUsername = !useAsUsername.isBlank() ? useAsUsername : "email";
    }

    //    todo: why are we passing name here if it's not used?
    // todo: use util class/method
    public boolean isSettingsValid() {
        return isValid(this.getIssuer(), "issuer")
                && isValid(this.getClientId(), "clientId")
                && isValid(this.getClientSecret(), "clientSecret")
                && isValid(this.getScopes(), "scopes")
                && isValid(this.getUseAsUsername(), "useAsUsername");
    }

    private boolean isValid(String value, String name) {
        return value != null && !value.isBlank();
    }

    private boolean isValid(Collection<String> value, String name) {
        return value != null && !value.isEmpty();
    }

    public void setScopes(String scopes) {
        this.scopes =
                Arrays.stream(scopes.split(",")).map(String::trim).collect(Collectors.toList());
    }
}
