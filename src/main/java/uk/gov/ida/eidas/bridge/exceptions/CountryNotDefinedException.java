package uk.gov.ida.eidas.bridge.exceptions;

public class CountryNotDefinedException extends RuntimeException {
    private String country;

    public CountryNotDefinedException(String country) {
        this.country = country;
    }

    public String getCountry() {
        return country;
    }
}
