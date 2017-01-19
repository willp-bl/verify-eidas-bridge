package uk.gov.ida.eidas.bridge.hacks;

import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter;
import org.opensaml.saml.saml2.metadata.AffiliationDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.security.x509.impl.BasicPKIXValidationInformation;
import org.opensaml.xmlsec.keyinfo.impl.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.provider.InlineX509DataProvider;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.PKIXSignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import uk.gov.ida.saml.metadata.NamelessPKIXValidationInformationResolver;
import uk.gov.ida.saml.metadata.PKIXSignatureValidationFilterProvider;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;

import static java.util.Collections.singletonList;

/**
 * The eIDAS reference code for the proxy node has a bug which causes RoleDescriptors
 * in the Metadata to be incorrectly signed (they have empty DigestValues and SignatureValues).
 * See https://ec.europa.eu/cefdigital/tracker/browse/EID-108 (note: visibility of this ticket is currently restricted).
 *
 * This is due to be fixed in the 1.1.1 release, but until all the member states have upgraded we
 * have a requirement to work around the issue.
 *
 * This class provides a MetadataFilter that checks the signature on EntityDescriptors but skips
 * signatures on RoleDescriptors if and only if they have empty values (which is the bug).
 *
 * The code is copied from {@link SignatureValidationFilter}.
 */
public class RoleDescriptorSkippingSignatureValidationFilter extends SignatureValidationFilter {
    private static final Logger log = LoggerFactory.getLogger(RoleDescriptorSkippingSignatureValidationFilter.class);

    /**
     * Duplicate of {@link PKIXSignatureValidationFilterProvider#get()}, except it returns
     * a {@link RoleDescriptorSkippingSignatureValidationFilter} instead of a {@link SignatureValidationFilter}
     */
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

    /**
     * Overrides {@link SignatureValidationFilter#processEntityDescriptor(EntityDescriptor)}. The code is a direct copy.
     * The only difference from the base implementation is that it skips signature validation on RoleDescriptors if the
     * SignatureValue is empty. This extra code is surrounded with &lt;hack&gt; comments.
     */
    @Override
    protected void processEntityDescriptor(@Nonnull final EntityDescriptor entityDescriptor) throws FilterException {
        final String entityID = entityDescriptor.getEntityID();
        log.trace("Processing EntityDescriptor: {}", entityID);

        if (entityDescriptor.isSigned()) {
            verifySignature(entityDescriptor, entityID, false);
        }

        final Iterator<RoleDescriptor> roleIter = entityDescriptor.getRoleDescriptors().iterator();
        while (roleIter.hasNext()) {
            final RoleDescriptor roleChild = roleIter.next();
            if (!roleChild.isSigned()) {
                log.trace("RoleDescriptor member '{}' was not signed, skipping signature processing...",
                    roleChild.getElementQName());
                continue;
            }
            // <hack> Skip role descriptors with broken signatures due to eIDAS bug EID-108.
            else if (hasBrokenSignatureValue(roleChild)) {
                log.info("Skipping signature validation on role descriptor to work around eidas bug EID-108");
                continue;
            }
            // </hack>
            else {
                log.error("Expected a broken signature on the RoleDescriptor, as per the configuration for this country. Perhaps the country has fixed the bug?");
                log.trace("Processing signed RoleDescriptor member: {}", roleChild.getElementQName());
            }

            try {
                final String roleID = getRoleIDToken(entityID, roleChild);
                verifySignature(roleChild, roleID, false);
            } catch (final FilterException e) {
                log.error("RoleDescriptor '{}' subordinate to entity '{}' failed signature verification, "
                        + "removing from metadata provider",
                    roleChild.getElementQName(), entityID);
                // Note that this is ok since we're iterating over an IndexedXMLObjectChildrenList directly,
                // rather than a sublist like in processEntityGroup, and iterator remove() is supported there.
                roleIter.remove();
            }
        }

        if (entityDescriptor.getAffiliationDescriptor() != null) {
            final AffiliationDescriptor affiliationDescriptor = entityDescriptor.getAffiliationDescriptor();
            if (!affiliationDescriptor.isSigned()) {
                log.trace("AffiliationDescriptor member was not signed, skipping signature processing...");
            } else {
                log.trace("Processing signed AffiliationDescriptor member with owner ID: {}",
                    affiliationDescriptor.getOwnerID());

                try {
                    verifySignature(affiliationDescriptor, affiliationDescriptor.getOwnerID(), false);
                } catch (final FilterException e) {
                    log.error("AffiliationDescriptor with owner ID '{}' subordinate to entity '{}' " +
                            "failed signature verification, removing from metadata provider",
                        affiliationDescriptor.getOwnerID(), entityID);
                    entityDescriptor.setAffiliationDescriptor(null);
                }
            }
        }
    }

    /**
     * Hack to detect whether a RoleDescriptor has a signature broken by eIDAS bug EID-108.
     *
     * Broken signatures have empty ./Signature/SignatureValues
     */
    private boolean hasBrokenSignatureValue(RoleDescriptor roleDescriptor) {
        Signature signature = roleDescriptor.getSignature();
        if (signature == null) {
            throw new NullPointerException("Expected RoleDescriptor to be signed, but it's signature was null");
        }
        Element dom = signature.getDOM();
        if (dom == null) {
            throw new NullPointerException("Couldn't get the DOM from the Signature element");
        }
        NodeList childNodes = dom.getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node node = childNodes.item(i);
            if ("SignatureValue".equals(node.getLocalName())) {
                if (Strings.isNullOrEmpty(node.getTextContent())) {
                    return true;
                }
            }
        }
        return false;
    }

}

