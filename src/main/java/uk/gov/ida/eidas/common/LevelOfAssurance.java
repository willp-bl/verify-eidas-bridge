package uk.gov.ida.eidas.common;

public enum LevelOfAssurance {

    LOW("http://eidas.europa.eu/LoA/low"),

    SUBSTANTIAL("http://eidas.europa.eu/LoA/substantial"),

    HIGH("http://eidas.europa.eu/LoA/high");

    private final String value;

    LevelOfAssurance(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }
}
