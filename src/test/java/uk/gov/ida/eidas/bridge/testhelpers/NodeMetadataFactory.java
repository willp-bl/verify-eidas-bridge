package uk.gov.ida.eidas.bridge.testhelpers;

import com.google.common.base.Throwables;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorBuilder;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.w3c.dom.Element;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.core.test.builders.metadata.EntityDescriptorBuilder;
import uk.gov.ida.saml.core.test.builders.metadata.IdpSsoDescriptorBuilder;
import uk.gov.ida.saml.core.test.builders.metadata.KeyDescriptorBuilder;
import uk.gov.ida.saml.core.test.builders.metadata.SignatureBuilder;
import uk.gov.ida.saml.serializers.XmlObjectToElementTransformer;
import uk.gov.ida.shared.utils.xml.XmlUtils;

import static uk.gov.ida.saml.core.test.builders.metadata.EndpointBuilder.anEndpoint;

public class NodeMetadataFactory {

    private static XmlObjectToElementTransformer<EntityDescriptor> entityDescriptorXmlObjectToElementTransformer = new XmlObjectToElementTransformer<>();

    public static String createNodeIdpMetadata(String entityID) {
        return createMetadata(createIdpEntityDescriptor(entityID));
    }

    public static EntityDescriptor createIdpEntityDescriptor(String entityID) {
        Signature entityDescriptorSignature = createSignature();
        KeyDescriptor keyDescriptor = KeyDescriptorBuilder.aKeyDescriptor().withX509ForSigning(TestCertificateStrings.TEST_PUBLIC_CERT).build();
        IDPSSODescriptor idpssoDescriptor = IdpSsoDescriptorBuilder
                .anIdpSsoDescriptor()
                .addKeyDescriptor(keyDescriptor)
                .build();
        try {
            return getEntityDescriptor(entityID, idpssoDescriptor, entityDescriptorSignature);
        } catch (MarshallingException | SignatureException e) {
            throw Throwables.propagate(e);
        }
    }

    public static EntityDescriptor createEntityDescriptorWithBrokenRoleDescriptorSignature(String entityID) {
        KeyDescriptor keyDescriptor = KeyDescriptorBuilder.aKeyDescriptor().withX509ForSigning(TestCertificateStrings.TEST_PUBLIC_CERT).build();
        Signature idpSSODescSignature = createSignature();
        IDPSSODescriptor idpssoDescriptor = new IDPSSODescriptorBuilder().buildObject();
        idpssoDescriptor.getKeyDescriptors().add(keyDescriptor);
        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
        idpssoDescriptor.getSingleSignOnServices().add(anEndpoint().buildSingleSignOnService());
        // Set the signature, but don't actually sign the element to reproduce the EID-108 bug:
        idpssoDescriptor.setSignature(idpSSODescSignature);

        Signature entityDescriptorSignature = createSignature();
        try {
            return getEntityDescriptor(entityID, idpssoDescriptor, entityDescriptorSignature);
        } catch (MarshallingException | SignatureException e) {
            throw Throwables.propagate(e);
        }
    }

    private static EntityDescriptor getEntityDescriptor(String entityID, IDPSSODescriptor idpssoDescriptor, Signature entityDescriptorSignature) throws MarshallingException, SignatureException {
        return EntityDescriptorBuilder
            .anEntityDescriptor()
            .withEntityId(entityID)
            .withIdpSsoDescriptor(idpssoDescriptor)
            .withSignature(entityDescriptorSignature)
            .build();
    }

    public static String createMetadata(EntityDescriptor entityDescriptor) {
        Element element = entityDescriptorXmlObjectToElementTransformer.apply(entityDescriptor);
        return XmlUtils.writeToString(element);
    }

    private static Signature createSignature() {
        TestCredentialFactory testCredentialFactory = new TestCredentialFactory(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT, TestCertificateStrings.METADATA_SIGNING_A_PRIVATE_KEY);
        Credential credential = testCredentialFactory.getSigningCredential();
        return SignatureBuilder
                .aSignature()
                .withSigningCredential(credential)
                .withX509Data(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT)
                .build();
    }
}
