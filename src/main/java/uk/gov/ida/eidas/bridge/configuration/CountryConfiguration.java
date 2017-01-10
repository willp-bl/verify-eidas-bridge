package uk.gov.ida.eidas.bridge.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class CountryConfiguration extends TrustStoreConfiguration {


    public String getEntityID() {
        return entityID;
    }

    @Valid
    @NotNull
    @JsonProperty
    public String entityID;

    public String getCountryCode() {
        return countryCode;
    }

    @Valid
    @NotNull
    @JsonProperty
    public String countryCode;
}
