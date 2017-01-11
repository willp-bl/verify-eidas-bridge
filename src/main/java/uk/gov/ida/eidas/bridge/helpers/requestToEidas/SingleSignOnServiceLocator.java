package uk.gov.ida.eidas.bridge.helpers.requestToEidas;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.eidas.bridge.exceptions.CountryNotDefinedException;
import uk.gov.ida.eidas.bridge.security.MetadataResolverRepository;

import java.util.List;

import static com.google.common.base.Throwables.propagate;
import static java.text.MessageFormat.format;

public class SingleSignOnServiceLocator {

    private static final Logger LOG = LoggerFactory.getLogger(SingleSignOnServiceLocator.class);

    private final MetadataResolverRepository metadataResolvers;

    public SingleSignOnServiceLocator(MetadataResolverRepository metadataResolvers) {
        this.metadataResolvers = metadataResolvers;
    }

    public String getSignOnUrl(String entityId) throws CountryNotDefinedException {
        MetadataResolver metadataResolver = metadataResolvers.fetch(entityId);
        EntityDescriptor idpEntityDescriptor;
        try {
            CriteriaSet criteria = new CriteriaSet(new EntityIdCriterion(entityId));
            idpEntityDescriptor = metadataResolver.resolveSingle(criteria);

        } catch (ResolverException e) {
            LOG.error("Exception when accessing metadata: {}", e);
            throw propagate(e);
        }

        if (idpEntityDescriptor != null) {
            final IDPSSODescriptor idpssoDescriptor = idpEntityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
            final List<SingleSignOnService> singleSignOnServices = idpssoDescriptor.getSingleSignOnServices();
            if (singleSignOnServices.size() == 0) {
                LOG.error("No singleSignOnServices present for IDP entityId: {}", entityId);
            } else {
                if (singleSignOnServices.size() > 1) {
                    LOG.warn("More than one singleSignOnService present: {} for {}", singleSignOnServices.size(), entityId);
                }
                return singleSignOnServices.get(0).getLocation();
            }
        }
        throw new RuntimeException(format("no entity descriptor for IDP: {0}", entityId));
    }
}
