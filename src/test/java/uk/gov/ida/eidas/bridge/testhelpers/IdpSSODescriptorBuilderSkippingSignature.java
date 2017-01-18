package uk.gov.ida.eidas.bridge.testhelpers;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorBuilder;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;

import java.util.ArrayList;
import java.util.List;

import static uk.gov.ida.saml.core.test.builders.metadata.EndpointBuilder.anEndpoint;
import static uk.gov.ida.saml.core.test.builders.metadata.SignatureBuilder.aSignature;


/**
 * Duplicate of {@link uk.gov.ida.saml.core.test.builders.metadata.IdpSsoDescriptorBuilder}, to build an IDPSSODescriptor with an invalid signature
 */
public class IdpSSODescriptorBuilderSkippingSignature {
    private List<KeyDescriptor> keyDescriptors = new ArrayList<>();
    private Signature signature = aSignature().build();

    static IdpSSODescriptorBuilderSkippingSignature anIdpSsoDescriptor() {
        return new IdpSSODescriptorBuilderSkippingSignature();
    }

    public IDPSSODescriptor build() throws SignatureException, MarshallingException {
        IDPSSODescriptor descriptor = new IDPSSODescriptorBuilder().buildObject();
        descriptor.getKeyDescriptors().addAll(keyDescriptors);

        descriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        descriptor.getSingleSignOnServices().add(anEndpoint().buildSingleSignOnService());

        // Set the signature, but don't actually sign the element to reproduce the EID-108 bug:
        descriptor.setSignature(signature);

        return descriptor;
    }

    public IdpSSODescriptorBuilderSkippingSignature addKeyDescriptor(KeyDescriptor keyDescriptor) {
        this.keyDescriptors.add(keyDescriptor);
        return this;
    }
}
