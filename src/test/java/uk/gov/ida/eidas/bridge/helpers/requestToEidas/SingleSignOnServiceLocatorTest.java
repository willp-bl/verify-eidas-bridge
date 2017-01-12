package uk.gov.ida.eidas.bridge.helpers.requestToEidas;

import com.google.common.base.Throwables;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import uk.gov.ida.eidas.bridge.helpers.EidasSamlBootstrap;
import uk.gov.ida.eidas.bridge.security.MetadataResolverRepository;
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
        EidasSamlBootstrap.bootstrap();
    }

    @Test
    public void shouldFetchSingleSignOnServiceLocationFromMetadata() {
        try {
            when(metadataResolver.resolveSingle(any(CriteriaSet.class))).thenReturn(new EntityDescriptorFactory().idpEntityDescriptor("myEntityId"));
        } catch (ResolverException e) {
            throw Throwables.propagate(e);
        }
        SingleSignOnServiceLocator singleSignOnServiceLocator = new SingleSignOnServiceLocator(metadataResolverRepository);
        when(metadataResolverRepository.fetch("myEntityId")).thenReturn(metadataResolver);
        String ssoLocation = singleSignOnServiceLocator.getSignOnUrl("myEntityId");
        assertEquals("http://foo.com/bar", ssoLocation);
    }
}
