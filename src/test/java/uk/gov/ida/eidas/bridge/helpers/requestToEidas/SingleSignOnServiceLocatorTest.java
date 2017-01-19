package uk.gov.ida.eidas.bridge.helpers.requestToEidas;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import uk.gov.ida.eidas.bridge.security.MetadataResolverRepository;
import uk.gov.ida.saml.core.IdaSamlBootstrap;
import uk.gov.ida.saml.core.test.builders.metadata.EntityDescriptorBuilder;
import uk.gov.ida.saml.metadata.test.factories.metadata.EntityDescriptorFactory;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SingleSignOnServiceLocatorTest {

    @Mock
    private MetadataResolver metadataResolver;

    @Mock
    private MetadataResolverRepository metadataResolverRepository;

    @Before
    public void before() {
        IdaSamlBootstrap.bootstrap();
    }

    @Test
    public void shouldFetchSingleSignOnServiceLocationFromMetadata() throws Exception {
        when(metadataResolver.resolveSingle(any(CriteriaSet.class))).thenReturn(new EntityDescriptorFactory().idpEntityDescriptor("myEntityId"));
        SingleSignOnServiceLocator singleSignOnServiceLocator = new SingleSignOnServiceLocator(metadataResolverRepository);
        when(metadataResolverRepository.fetch("myEntityId")).thenReturn(metadataResolver);
        String ssoLocation = singleSignOnServiceLocator.getSignOnUrl("myEntityId");
        assertEquals("http://foo.com/bar", ssoLocation);
    }

    @Test(expected = RuntimeException.class)
    public void shouldErrorIfNoRoleDescriptorsFound() throws Exception {
        EntityDescriptor entityDescriptorWithoutRoleDescriptor = EntityDescriptorBuilder.anEntityDescriptor().withIdpSsoDescriptor(null).build();

        when(metadataResolver.resolveSingle(any(CriteriaSet.class))).thenReturn(entityDescriptorWithoutRoleDescriptor);
        SingleSignOnServiceLocator singleSignOnServiceLocator = new SingleSignOnServiceLocator(metadataResolverRepository);
        when(metadataResolverRepository.fetch("myEntityId")).thenReturn(metadataResolver);
        String ssoLocation = singleSignOnServiceLocator.getSignOnUrl("myEntityId");
        assertEquals("http://foo.com/bar", ssoLocation);
    }
}
