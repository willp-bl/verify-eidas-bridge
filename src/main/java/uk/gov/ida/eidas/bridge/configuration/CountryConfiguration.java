package uk.gov.ida.eidas.bridge.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class CountryConfiguration extends TrustStoreConfiguration {


    public CountryConfiguration() {
    }

    public CountryConfiguration(String entityID, String countryCode, String overriddenSignOnUrl, boolean workaroundBrokenRoleDescriptorSignatures) {
        this.entityID = entityID;
        this.countryCode = countryCode;
        this.overriddenSignOnUrl = overriddenSignOnUrl;
        this.workaroundBrokenRoleDescriptorSignatures = workaroundBrokenRoleDescriptorSignatures;
    }

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

    @Valid
    @JsonProperty
    public boolean workaroundBrokenRoleDescriptorSignatures = false;

    public boolean workaroundBrokenRoleDescriptorSignatures() {
        return workaroundBrokenRoleDescriptorSignatures;
    }

    @Valid
    @JsonProperty
    private String overriddenSignOnUrl;

    public String getOverriddenSignOnUrl() {
        return overriddenSignOnUrl;
    }
}
