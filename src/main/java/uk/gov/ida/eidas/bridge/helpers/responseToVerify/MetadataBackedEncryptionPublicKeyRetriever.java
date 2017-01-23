package uk.gov.ida.eidas.bridge.helpers.responseToVerify;

import com.google.common.base.Throwables;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;

import java.security.PublicKey;
import java.util.NoSuchElementException;
import java.util.Optional;

public class MetadataBackedEncryptionPublicKeyRetriever {
    private final MetadataCredentialResolver metadataCredentialResolver;

    public MetadataBackedEncryptionPublicKeyRetriever(MetadataCredentialResolver metadataCredentialResolver) {
        this.metadataCredentialResolver = metadataCredentialResolver;
    }

    public PublicKey retrieveKey(String entityId) {
        try {
            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(new EntityIdCriterion(entityId));
            criteriaSet.add(new EntityRoleCriterion(SPSSODescriptor.DEFAULT_ELEMENT_NAME));
            criteriaSet.add(new UsageCriterion(UsageType.ENCRYPTION));
            Credential credential = Optional.ofNullable(metadataCredentialResolver.resolveSingle(criteriaSet)).orElseThrow(() -> new NoSuchElementException("No encryption key found for entityId " + entityId));
            return credential.getPublicKey();
        } catch (ResolverException e) {
            throw Throwables.propagate(e);
        }
    }
}
