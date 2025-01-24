package stirling.software.SPDF.utils.validation;

import java.util.Collection;

public class CollectionValidator implements Validator<Collection<String>> {

    @Override
    public boolean validate(Collection<String> input, String path) {
        return input != null && !input.isEmpty();
    }
}
