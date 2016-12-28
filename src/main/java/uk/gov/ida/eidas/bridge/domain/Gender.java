package uk.gov.ida.eidas.bridge.domain;

import static java.util.Arrays.stream;

public enum Gender {
    FEMALE("Female"),
    MALE("Male"),
    NOT_SPECIFIED("Not Specified");

    private String value;

    Gender(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static Gender fromString(String string) {
        return stream(values())
            .filter(x -> x.getValue().equalsIgnoreCase(string))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Not a legal value for gender: " + string));
    }
}
