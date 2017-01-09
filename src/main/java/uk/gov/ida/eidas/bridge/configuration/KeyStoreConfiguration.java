package uk.gov.ida.eidas.bridge.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class KeyStoreConfiguration extends TrustStoreConfiguration {
    @JsonProperty
    @NotNull
    @Valid
    protected String alias;

    public String getAlias() {
        return alias;
    }
}
