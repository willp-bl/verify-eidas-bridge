package uk.gov.ida.eidas.bridge;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.Configuration;
import uk.gov.ida.saml.metadata.MetadataConfiguration;

public class BridgeConfiguration extends Configuration {

    @JsonProperty
    private MetadataConfiguration metadata;

    public MetadataConfiguration getMetadataConfiguration() {
        return metadata;
    }

}
