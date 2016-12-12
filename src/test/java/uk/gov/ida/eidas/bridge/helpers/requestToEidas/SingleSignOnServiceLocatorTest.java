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
import uk.gov.ida.eidas.bridge.helpers.requestToEidas.SingleSignOnServiceLocator;
import uk.gov.ida.saml.metadata.test.factories.metadata.EntityDescriptorFactory;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SingleSignOnServiceLocatorTest {

    @Mock
    MetadataResolver metadataResolver;

    @Before
    public void before() {
        try {
            when(metadataResolver.resolveSingle(any(CriteriaSet.class))).thenReturn(new EntityDescriptorFactory().idpEntityDescriptor("myEntityId"));
        } catch (ResolverException e) {
            throw Throwables.propagate(e);
        }
    }
    @Test
    public void shouldFetchSingleSignOnServiceLocationFromMetadata() {
        SingleSignOnServiceLocator singleSignOnServiceLocator = new SingleSignOnServiceLocator(metadataResolver);
        String ssoLocation = singleSignOnServiceLocator.getSignOnUrl("myEntityId");
        assertEquals("http://foo.com/bar", ssoLocation);
    }
}
