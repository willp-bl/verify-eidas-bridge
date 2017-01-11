package uk.gov.ida.eidas.bridge.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.client.JerseyClientConfiguration;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.List;

public class EidasMetadataConfiguration {

    private EidasMetadataConfiguration(){};

    public Integer getMinRefreshDelay() {
        return minRefreshDelay;
    }

    public Integer getMaxRefreshDelay() {
        return maxRefreshDelay;
    }

    public JerseyClientConfiguration getClient() {
        return client;
    }

    public List<CountryConfiguration> getCountries() {
        return countries;
    }

    /* Used to set {@link org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider#minRefreshDelay} */
    @Valid
    @NotNull
    @JsonProperty
    private Integer minRefreshDelay;

    /* Used to set {@link org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider#maxRefreshDelay} */
    @Valid
    @NotNull
    @JsonProperty
    private Integer maxRefreshDelay;

    @Valid
    @NotNull
    @JsonProperty
    private JerseyClientConfiguration client;

    @Valid
    @NotNull
    @NotEmpty
    @JsonProperty
    private List<CountryConfiguration> countries;

}
