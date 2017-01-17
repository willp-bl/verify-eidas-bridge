package uk.gov.ida.eidas.bridge.testhelpers;

import org.apache.commons.lang3.StringUtils;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorBuilder;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import uk.gov.ida.saml.core.test.TestEntityIds;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static uk.gov.ida.saml.core.test.builders.metadata.EndpointBuilder.anEndpoint;
import static uk.gov.ida.saml.core.test.builders.metadata.KeyDescriptorBuilder.aKeyDescriptor;
import static uk.gov.ida.saml.core.test.builders.metadata.KeyInfoBuilder.aKeyInfo;
import static uk.gov.ida.saml.core.test.builders.metadata.SignatureBuilder.aSignature;
import static uk.gov.ida.saml.core.test.builders.metadata.X509CertificateBuilder.aX509Certificate;
import static uk.gov.ida.saml.core.test.builders.metadata.X509DataBuilder.aX509Data;


/**
 * Duplicate of {@link uk.gov.ida.saml.core.test.builders.metadata.IdpSsoDescriptorBuilder}, to build an IDPSSODescriptor with an invalid signature
 */
public class IdpSSODescriptorBuilderSkippingSignature {
    private String entityId = TestEntityIds.HUB_ENTITY_ID;
    private Optional<String> protocol = Optional.ofNullable(SAMLConstants.SAML20P_NS);
    private Optional<SingleSignOnService> singleSignOnService = Optional.ofNullable(anEndpoint().buildSingleSignOnService());
    private List<KeyDescriptor> keyDescriptors = new ArrayList<>();
    private boolean addDefaultSigningKey = true;
    private KeyDescriptor defaultSigningKeyDescriptor = aKeyDescriptor().withKeyInfo(aKeyInfo().withKeyName(TestEntityIds.HUB_ENTITY_ID).withX509Data(aX509Data().withX509Certificate(aX509Certificate().build()).build()).build()).build();
    private boolean shouldBeSigned = true;
    private Optional<Signature> signature = Optional.ofNullable(aSignature().build());

    public static IdpSSODescriptorBuilderSkippingSignature anIdpSsoDescriptor() {
        return new IdpSSODescriptorBuilderSkippingSignature();
    }

    public IDPSSODescriptor build() throws SignatureException, MarshallingException {
        IDPSSODescriptor descriptor = new IDPSSODescriptorBuilder().buildObject();

        if (protocol.isPresent()) {
            descriptor.addSupportedProtocol(protocol.get());
        }

        if (singleSignOnService.isPresent()) {
            descriptor.getSingleSignOnServices().add(singleSignOnService.get());
        }

        if (addDefaultSigningKey) {
            descriptor.getKeyDescriptors().add(defaultSigningKeyDescriptor);
        }
        for (KeyDescriptor keyDescriptor : keyDescriptors) {
            descriptor.getKeyDescriptors().add(keyDescriptor);
        }

        if (signature.isPresent() && StringUtils.isNotEmpty(entityId)) {
            descriptor.setSignature(signature.get());

            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(descriptor).marshall(descriptor);
            if (shouldBeSigned) {
                Signer.signObject(descriptor.getSignature());
            }
        }

        return descriptor;
    }

    public IdpSSODescriptorBuilderSkippingSignature withSupportedProtocol(String protocol) {
        this.protocol = Optional.ofNullable(protocol);
        return this;
    }

    public IdpSSODescriptorBuilderSkippingSignature withSingleSignOnService(SingleSignOnService singleSignOnService) {
        this.singleSignOnService = Optional.ofNullable(singleSignOnService);
        return this;
    }

    public IdpSSODescriptorBuilderSkippingSignature addKeyDescriptor(KeyDescriptor keyDescriptor) {
        this.keyDescriptors.add(keyDescriptor);
        return this;
    }

    public IdpSSODescriptorBuilderSkippingSignature withoutDefaultSigningKey() {
        this.addDefaultSigningKey = false;
        return this;
    }


    public IdpSSODescriptorBuilderSkippingSignature withoutSigning() {
        this.shouldBeSigned = false;
        return this;
    }
}
