package stirling.software.SPDF.utils.validation;

import java.util.Collection;

import stirling.software.SPDF.model.provider.Provider;

public class Validator {

    public static boolean validateSettings(Provider provider) {
        if (provider == null) {
            return false;
        }

        if (isStringEmpty(provider.getClientId())) {
            return false;
        }

        if (isStringEmpty(provider.getClientSecret())) {
            return false;
        }

        if (isCollectionEmpty(provider.getScopes())) {
            return false;
        }

        return !isStringEmpty(provider.getUseAsUsername());
    }

    private static boolean isStringEmpty(String input) {
        return input == null || input.isBlank();
    }

    private static boolean isCollectionEmpty(Collection<String> input) {
        return input == null || input.isEmpty();
    }
}
