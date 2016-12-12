package uk.gov.ida.eidas.bridge.helpers.responseToVerify;

import com.google.common.base.Throwables;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.X509Certificate;
import uk.gov.ida.common.shared.security.X509CertificateFactory;

import java.security.PublicKey;
import java.util.NoSuchElementException;

public class MetadataBackedEncryptionPublicKeyRetriever {
    private final MetadataResolver metadataResolver;

    public MetadataBackedEncryptionPublicKeyRetriever(MetadataResolver metadataResolver) {
        this.metadataResolver = metadataResolver;
    }

    public PublicKey retrieveKey(String entityId) {
        CriteriaSet criteria = new CriteriaSet(new EntityIdCriterion(entityId));
        EntityDescriptor entityDescriptor;
        try {
            entityDescriptor = metadataResolver.resolveSingle(criteria);
        } catch (ResolverException e) {
            throw Throwables.propagate(e);
        }
        SPSSODescriptor spssoDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        KeyDescriptor keyDescriptor = spssoDescriptor.getKeyDescriptors()
            .stream()
            .filter(x -> x.getUse() == UsageType.ENCRYPTION)
            .findFirst()
            .orElseThrow(() -> new NoSuchElementException("No encryption key found for entityId " + entityId));
        X509Certificate x509Certificate = keyDescriptor.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);
        java.security.cert.X509Certificate certificate = new X509CertificateFactory().createCertificate(x509Certificate.getValue());
        return certificate.getPublicKey();
    }
}
