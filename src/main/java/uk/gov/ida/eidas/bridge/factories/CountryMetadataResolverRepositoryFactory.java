package uk.gov.ida.eidas.bridge.factories;

import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.setup.Environment;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import uk.gov.ida.eidas.bridge.configuration.CountryConfiguration;
import uk.gov.ida.eidas.bridge.configuration.EidasMetadataConfiguration;
import uk.gov.ida.eidas.bridge.security.MetadataResolverRepository;
import uk.gov.ida.saml.metadata.ExpiredCertificateMetadataFilter;
import uk.gov.ida.saml.metadata.PKIXSignatureValidationFilterProvider;
import uk.gov.ida.saml.metadata.modules.MetadataModule;

import javax.ws.rs.client.Client;
import java.net.URI;
import java.util.Map;
import java.util.stream.Collectors;

class CountryMetadataResolverRepositoryFactory {

    private final MetadataModule metadataModule = new MetadataModule();

    private MetadataResolver getCountryMetadataResolver(CountryConfiguration config, Integer minRefreshDelay, Integer maxRefreshDelay, Client client) {
        PKIXSignatureValidationFilterProvider pkixSignatureValidationFilterProvider = new PKIXSignatureValidationFilterProvider(config.getKeyStore());
        return metadataModule.metadataResolver(URI.create(config.entityID), maxRefreshDelay, minRefreshDelay, client, new ExpiredCertificateMetadataFilter(), pkixSignatureValidationFilterProvider);
    }

    private Map<String, MetadataResolver> getCountryMetadataResolvers(Environment environment, EidasMetadataConfiguration configuration) {
        Client client = createClient(environment, configuration);
        Integer maxRefreshDelay = configuration.getMaxRefreshDelay();
        Integer minRefreshDelay = configuration.getMinRefreshDelay();
        return configuration.getCountries().stream().collect(Collectors.toMap(
                CountryConfiguration::getEntityID,
                config -> getCountryMetadataResolver(config, minRefreshDelay, maxRefreshDelay, client)
        ));
    }

    private Client createClient(Environment environment, EidasMetadataConfiguration eidasMetadataConfgiruation) {
        return new JerseyClientBuilder(environment).using(eidasMetadataConfgiruation.getClient()).build("country-metadata-client");
    }

    MetadataResolverRepository createRepository(Environment environment, EidasMetadataConfiguration eidasMetadataConfiguration) {
        return new MetadataResolverRepository(getCountryMetadataResolvers(environment, eidasMetadataConfiguration));
    }
}
