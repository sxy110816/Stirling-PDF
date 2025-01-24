package stirling.software.SPDF.utils.validation;

public interface Validator<T> {

    boolean validate(T input, String path);
}
