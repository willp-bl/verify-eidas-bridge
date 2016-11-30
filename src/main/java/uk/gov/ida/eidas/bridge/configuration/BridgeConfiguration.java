package uk.gov.ida.eidas.bridge.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.Configuration;
import org.dhatim.dropwizard.jwt.cookie.authentication.JwtCookieAuthConfiguration;
import uk.gov.ida.saml.metadata.MetadataConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class BridgeConfiguration extends Configuration {

    @JsonProperty
    @Valid
    private MetadataConfiguration verifyMetadata;

    @JsonProperty
    @Valid
    private MetadataConfiguration eidasMetadata;

    @JsonProperty
    @NotNull
    private String eidasNodeEntityId;

    @JsonProperty
    @NotNull
    private String bridgeEntityId;

    @JsonProperty
    @NotNull
    private String hostname;

    @NotNull
    @JsonProperty("signingKeyStore")
    @Valid
    private KeyStoreConfiguration signingKeyStoreConfiguration;

    @NotNull
    @JsonProperty("encryptingKeyStore")
    @Valid
    private KeyStoreConfiguration encryptingKeyStoreConfiguration;

    @Valid
    @NotNull
    private JwtCookieAuthConfiguration sessionCookie = new JwtCookieAuthConfiguration();


    public MetadataConfiguration getVerifyMetadataConfiguration() {
        return verifyMetadata;
    }

    public MetadataConfiguration getEidasMetadataConfiguration() {
        return eidasMetadata;
    }

    public KeyStoreConfiguration getSigningKeyStoreConfiguration() {
        return signingKeyStoreConfiguration;
    }

    public KeyStoreConfiguration getEncryptingKeyStoreConfiguration() {
        return encryptingKeyStoreConfiguration;
    }

    public String getHostname() {
        return hostname;
    }

    public String getEidasNodeEntityId() {
        return eidasNodeEntityId;
    }

    public JwtCookieAuthConfiguration getSessionCookie() {
        return sessionCookie;
    }

    public String getBridgeEntityId() {
        return bridgeEntityId;
    }
}
