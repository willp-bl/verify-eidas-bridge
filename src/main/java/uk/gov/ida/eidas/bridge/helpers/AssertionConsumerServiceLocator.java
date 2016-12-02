package uk.gov.ida.eidas.bridge.helpers;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static com.google.common.base.Throwables.propagate;
import static java.text.MessageFormat.format;

public class AssertionConsumerServiceLocator {
    private static final Logger LOG = LoggerFactory.getLogger(SingleSignOnServiceLocator.class);

    private final MetadataResolver metadataResolver;

    public AssertionConsumerServiceLocator(MetadataResolver metadataResolver) {
        this.metadataResolver = metadataResolver;
    }

    public String getAssertionConsumerServiceLocation(String entityId) {
        EntityDescriptor spEntityDescriptor;
        try {
            CriteriaSet criteria = new CriteriaSet(new EntityIdCriterion(entityId));
            spEntityDescriptor = metadataResolver.resolveSingle(criteria);

        } catch (ResolverException e) {
            LOG.error("Exception when accessing metadata: {}", e);
            throw propagate(e);
        }

        if (spEntityDescriptor != null) {
            final SPSSODescriptor spssoDescriptor = spEntityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
            final List<AssertionConsumerService> assertionConsumerServices = spssoDescriptor.getAssertionConsumerServices();
            if (assertionConsumerServices.size() == 0) {
                LOG.error("No assertionConsumerServices present for IDP entityId: {}", entityId);
            } else {
                if (assertionConsumerServices.size() > 1) {
                    LOG.warn("More than one assertionConsumerService present: {} for {}", assertionConsumerServices.size(), entityId);
                }
                return assertionConsumerServices.get(0).getLocation();
            }
        }
        throw new RuntimeException(format("no entity descriptor for IDP: {0}", entityId));
    }
}
