package uk.gov.ida.eidas.bridge.apprule;

import com.google.common.io.Resources;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.junit.Test;
import org.opensaml.saml.metadata.criteria.entity.impl.EntityDescriptorCriterionPredicateRegistry;
import org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter;
import uk.gov.ida.eidas.bridge.hacks.RoleDescriptorSkippingSignatureValidationFilter;
import uk.gov.ida.eidas.bridge.helpers.requestToEidas.SingleSignOnServiceLocator;
import uk.gov.ida.eidas.bridge.security.MetadataResolverRepository;
import uk.gov.ida.saml.core.IdaSamlBootstrap;
import uk.gov.ida.saml.metadata.EntitiesDescriptorNameCriterion;
import uk.gov.ida.saml.metadata.EntitiesDescriptorNamePredicate;
import uk.gov.ida.saml.metadata.ExpiredCertificateMetadataFilter;
import uk.gov.ida.saml.metadata.JerseyClientMetadataResolver;

import java.net.URI;
import java.security.KeyStore;
import java.util.Timer;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SwedenTest {
    @Test
    public void should() throws Exception {
        IdaSamlBootstrap.bootstrap();
        JerseyClientMetadataResolver metadataResolver = new JerseyClientMetadataResolver(
            new Timer(),
            JerseyClientBuilder.createClient(),
            URI.create("https://eunode.eidastest.se/EidasNode/ServiceMetadata"));
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.initialize();
        metadataResolver.setParserPool(parserPool);
        metadataResolver.setId("MetadataModule.MetadataResolver");

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(Resources.getResource("se_trust.jks").openStream(), "Password".toCharArray());
        SignatureValidationFilter signatureValidationFilter = RoleDescriptorSkippingSignatureValidationFilter.fromKeystore(keyStore);
        ExpiredCertificateMetadataFilter expiredCertificateMetadataFilter = new ExpiredCertificateMetadataFilter();
        metadataResolver.setMetadataFilter(metadata -> signatureValidationFilter.filter(expiredCertificateMetadataFilter.filter(metadata)));

        metadataResolver.setRequireValidMetadata(true);
        metadataResolver.setFailFastInitialization(false);
        metadataResolver.setMaxRefreshDelay(1000);
        metadataResolver.setMinRefreshDelay(1000);
        metadataResolver.setResolveViaPredicatesOnly(true);

        EntityDescriptorCriterionPredicateRegistry registry = new EntityDescriptorCriterionPredicateRegistry();
        registry.register(EntitiesDescriptorNameCriterion.class, EntitiesDescriptorNamePredicate.class);
        metadataResolver.setCriterionPredicateRegistry(registry);

        metadataResolver.initialize();
        MetadataResolverRepository metadataResolverRepository = mock(MetadataResolverRepository.class);
        SingleSignOnServiceLocator singleSignOnServiceLocator = new SingleSignOnServiceLocator(metadataResolverRepository);
        when(metadataResolverRepository.fetch("https://eunode.eidastest.se/EidasNode/ServiceMetadata")).thenReturn(metadataResolver);
        String ssoLocation = singleSignOnServiceLocator.getSignOnUrl("https://eunode.eidastest.se/EidasNode/ServiceMetadata");
        assertEquals("https://eunode.eidastest.se/EidasNode/ColleagueRequest", ssoLocation);
    }
}
