package uk.gov.ida.eidas.bridge.factories;

import io.dropwizard.setup.Environment;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import uk.gov.ida.saml.metadata.ExpiredCertificateMetadataFilter;
import uk.gov.ida.saml.metadata.KeyStoreLoader;
import uk.gov.ida.saml.metadata.MetadataConfiguration;
import uk.gov.ida.saml.metadata.PKIXSignatureValidationFilterProvider;
import uk.gov.ida.saml.metadata.modules.MetadataModule;

import java.security.KeyStore;

public class MetadataFactory {

    private final Environment environment;
    private final MetadataConfiguration metadataConfiguration;

    private MetadataResolver metadataResolver = null;

    public MetadataFactory(Environment environment, MetadataConfiguration metadataConfiguration) {
        this.environment = environment;
        this.metadataConfiguration = metadataConfiguration;
    }

    public MetadataResolver getMetadataResolver() {
        if (metadataResolver != null) {
            return metadataResolver;
        }
        else {
            KeyStore keyStore = new KeyStoreLoader().load(
                metadataConfiguration.getTrustStorePath(),
                metadataConfiguration.getTrustStorePassword());
            metadataResolver = new MetadataModule().metadataResolver(
                metadataConfiguration.getUri(),
                metadataConfiguration.getMaxRefreshDelay(),
                metadataConfiguration.getMinRefreshDelay(),
                environment,
                metadataConfiguration,
                new ExpiredCertificateMetadataFilter(),
                new PKIXSignatureValidationFilterProvider(keyStore)
            );
            return metadataResolver;
        }
    }
}
