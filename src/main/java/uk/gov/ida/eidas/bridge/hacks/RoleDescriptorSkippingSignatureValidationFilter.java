package uk.gov.ida.eidas.bridge.hacks;

import com.google.common.base.Throwables;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.x509.impl.BasicPKIXValidationInformation;
import org.opensaml.xmlsec.keyinfo.impl.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.provider.InlineX509DataProvider;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.PKIXSignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.saml.metadata.NamelessPKIXValidationInformationResolver;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;

import static java.util.Collections.singletonList;

public class RoleDescriptorSkippingSignatureValidationFilter extends SignatureValidationFilter {
    private static final Logger log = LoggerFactory.getLogger(RoleDescriptorSkippingSignatureValidationFilter.class);

    public static RoleDescriptorSkippingSignatureValidationFilter fromKeystore(KeyStore metadataTrustStore) {
        ArrayList<String> aliases;
        BasicPKIXValidationInformation basicPKIXValidationInformation = null;
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            aliases = Collections.list(metadataTrustStore.aliases());
            ArrayList<X509Certificate> trustAnchors = new ArrayList<>();
            for (String alias : aliases) {
                trustAnchors.add((X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(metadataTrustStore.getCertificate(alias).getEncoded())));
            }
            basicPKIXValidationInformation = new BasicPKIXValidationInformation(trustAnchors, Collections.emptyList(), 0);
        } catch (KeyStoreException | CertificateException e) {
            Throwables.propagate(e);
        }
        SignatureTrustEngine trustEngine = new PKIXSignatureTrustEngine(
            new NamelessPKIXValidationInformationResolver(singletonList(basicPKIXValidationInformation)),
            new BasicProviderKeyInfoCredentialResolver(singletonList(new InlineX509DataProvider()))
        );

        RoleDescriptorSkippingSignatureValidationFilter validationFilter = new RoleDescriptorSkippingSignatureValidationFilter(trustEngine);
        validationFilter.setRequireSignedRoot(true);
        return validationFilter;
    }

    private RoleDescriptorSkippingSignatureValidationFilter(@Nonnull SignatureTrustEngine engine) { super(engine); }

    protected void processEntityDescriptor(@Nonnull final EntityDescriptor entityDescriptor) throws FilterException {
        final String entityID = entityDescriptor.getEntityID();
        log.trace("Processing EntityDescriptor: {}", entityID);

        if (entityDescriptor.isSigned()) {
            verifySignature(entityDescriptor, entityID, false);
        }
    }

}
