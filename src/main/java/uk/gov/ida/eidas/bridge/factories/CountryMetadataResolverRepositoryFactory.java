package uk.gov.ida.eidas.bridge.factories;

import com.google.common.base.Throwables;
import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.setup.Environment;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.opensaml.saml.metadata.criteria.entity.impl.EntityDescriptorCriterionPredicateRegistry;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter;
import uk.gov.ida.eidas.bridge.configuration.CountryConfiguration;
import uk.gov.ida.eidas.bridge.configuration.EidasMetadataConfiguration;
import uk.gov.ida.eidas.bridge.hacks.RoleDescriptorSkippingSignatureValidationFilter;
import uk.gov.ida.eidas.bridge.security.MetadataResolverRepository;
import uk.gov.ida.saml.core.IdaSamlBootstrap;
import uk.gov.ida.saml.metadata.EntitiesDescriptorNameCriterion;
import uk.gov.ida.saml.metadata.EntitiesDescriptorNamePredicate;
import uk.gov.ida.saml.metadata.ExpiredCertificateMetadataFilter;
import uk.gov.ida.saml.metadata.JerseyClientMetadataResolver;
import uk.gov.ida.saml.metadata.PKIXSignatureValidationFilterProvider;
import uk.gov.ida.saml.metadata.modules.MetadataModule;

import javax.ws.rs.client.Client;
import java.net.URI;
import java.security.KeyStore;
import java.util.Map;
import java.util.Timer;
import java.util.stream.Collectors;

class CountryMetadataResolverRepositoryFactory {

    private final MetadataModule metadataModule = new MetadataModule();

    private MetadataResolver getCountryMetadataResolver(CountryConfiguration config, Integer minRefreshDelay, Integer maxRefreshDelay, Client client) {
        return getRoleDescriptorSkippingMetadataResolver(config.getKeyStore(), URI.create(config.entityID), maxRefreshDelay, minRefreshDelay, client, new ExpiredCertificateMetadataFilter());
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

    /**
     * Duplicate of {@link MetadataModule#metadataResolver}, except the resolver is built with a
     * a {@link RoleDescriptorSkippingSignatureValidationFilter} instead of a {@link SignatureValidationFilter}
     */
    private MetadataResolver getRoleDescriptorSkippingMetadataResolver(
        KeyStore keystore,
        URI metadataUri,
        int maxRefreshDelay,
        int minRefreshDelay,
        Client client,
        ExpiredCertificateMetadataFilter expiredCertificateMetadataFilter) {
        try {
            IdaSamlBootstrap.bootstrap();
            JerseyClientMetadataResolver metadataResolver = new JerseyClientMetadataResolver(
                new Timer(),
                client,
                metadataUri);
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.initialize();
            metadataResolver.setParserPool(parserPool);
            metadataResolver.setId("MetadataModule.MetadataResolver");

            SignatureValidationFilter signatureValidationFilter = RoleDescriptorSkippingSignatureValidationFilter.fromKeystore(keystore);
            metadataResolver.setMetadataFilter(metadata -> signatureValidationFilter.filter(expiredCertificateMetadataFilter.filter(metadata)));

            metadataResolver.setRequireValidMetadata(true);
            metadataResolver.setFailFastInitialization(false);
            metadataResolver.setMaxRefreshDelay(maxRefreshDelay);
            metadataResolver.setMinRefreshDelay(minRefreshDelay);
            metadataResolver.setResolveViaPredicatesOnly(true);

            EntityDescriptorCriterionPredicateRegistry registry = new EntityDescriptorCriterionPredicateRegistry();
            registry.register(EntitiesDescriptorNameCriterion.class, EntitiesDescriptorNamePredicate.class);
            metadataResolver.setCriterionPredicateRegistry(registry);

            metadataResolver.initialize();
            return metadataResolver;
        } catch (ComponentInitializationException e) {
            throw Throwables.propagate(e);
        }
    }
}
