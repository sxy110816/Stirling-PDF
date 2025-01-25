package stirling.software.SPDF.utils.validation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;
import stirling.software.SPDF.model.provider.GitHubProvider;
import stirling.software.SPDF.model.provider.GoogleProvider;
import stirling.software.SPDF.model.provider.KeycloakProvider;
import stirling.software.SPDF.model.provider.Provider;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ValidatorTest {

    @Test
    void testSuccessfulValidation() {
        var provider = mock(GitHubProvider.class);

        when(provider.getClientId()).thenReturn("clientId");
        when(provider.getClientSecret()).thenReturn("clientSecret");
        when(provider.getScopes()).thenReturn(List.of("read:user"));
        when(provider.getUseAsUsername()).thenReturn("email");

        assertTrue(Validator.validateSettings(provider));
    }

    @ParameterizedTest
    @MethodSource("providerParams")
    void testUnsuccessfulValidation(Provider provider) {
        assertFalse(Validator.validateSettings(provider));
    }

    public static Stream<Arguments> providerParams() {
        var generic = new GitHubProvider(null, "clientSecret", "  ");
        var google = new GoogleProvider(null, "clientSecret", "email");
        var github = new GitHubProvider("clientId", "", "email");
        var keycloak = new KeycloakProvider("issuer", "clientId", "clientSecret", "         ");

        return Stream.of(
                Arguments.of(generic),
                Arguments.of(google),
                Arguments.of(github),
                Arguments.of(keycloak)
        );
    }

}