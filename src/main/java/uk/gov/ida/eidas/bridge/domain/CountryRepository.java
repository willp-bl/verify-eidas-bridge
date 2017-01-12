package uk.gov.ida.eidas.bridge.domain;

import uk.gov.ida.eidas.bridge.exceptions.CountryNotDefinedException;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class CountryRepository {
    private final Map<String, String> countryCodeEntityIdMap;

    public CountryRepository(Map<String, String> countryCodeEntityIdMap) {
        this.countryCodeEntityIdMap = countryCodeEntityIdMap;
    }

    public String fetchEntityId(String countryCode) throws CountryNotDefinedException {
        return Optional.ofNullable(countryCodeEntityIdMap.get(countryCode)).orElseThrow(() -> new CountryNotDefinedException(countryCode));
    }

    public Set<String> getEnabledCountries() {
        return countryCodeEntityIdMap.keySet();
    }
}
