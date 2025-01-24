package stirling.software.SPDF.utils.validation;

public class StringValidator implements Validator<String> {

    @Override
    public boolean validate(String input, String path) {
        return input != null && !input.isBlank();
    }
}
