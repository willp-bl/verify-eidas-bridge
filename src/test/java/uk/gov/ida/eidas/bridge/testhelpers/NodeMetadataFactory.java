package uk.gov.ida.eidas.bridge.testhelpers;

import com.google.common.base.Throwables;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
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

public class NodeMetadataFactory {

    private static XmlObjectToElementTransformer<EntityDescriptor> entityDescriptorXmlObjectToElementTransformer = new XmlObjectToElementTransformer<>();

    public static String createNodeIdpMetadata(String entityID) {
        return createMetadata(createIdpEntityDescriptor(entityID));
    }

    public static String createNodeIdpMetadataWithoutSignedIDPSSODescriptor(String entityID) {
        return createMetadata(createIdpEntityDescriptorWithoutIDPSSODescriptor(entityID));
    }

    public static EntityDescriptor createIdpEntityDescriptorWithoutIDPSSODescriptor(String entityID) {
        Signature signature = createSignature(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT, TestCertificateStrings.METADATA_SIGNING_A_PRIVATE_KEY);
        KeyDescriptor keyDescriptor = KeyDescriptorBuilder.aKeyDescriptor().withX509ForSigning(TestCertificateStrings.TEST_PUBLIC_CERT).build();
        try {
            IDPSSODescriptor idpssoDescriptor = IdpSSODescriptorBuilderSkippingSignature
                .anIdpSsoDescriptor()
                .addKeyDescriptor(keyDescriptor)
                .withoutSigning()
                .build();
            return EntityDescriptorBuilder
                .anEntityDescriptor()
                .withEntityId(entityID)
                .withIdpSsoDescriptor(idpssoDescriptor)
                .withSignature(signature)
                .build();
        } catch (MarshallingException | SignatureException e) {
            throw Throwables.propagate(e);
        }
    }

    public static EntityDescriptor createIdpEntityDescriptor(String entityID) {
        Signature signature = createSignature(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT, TestCertificateStrings.METADATA_SIGNING_A_PRIVATE_KEY);
        KeyDescriptor keyDescriptor = KeyDescriptorBuilder.aKeyDescriptor().withX509ForSigning(TestCertificateStrings.TEST_PUBLIC_CERT).build();
        IDPSSODescriptor idpssoDescriptor = IdpSsoDescriptorBuilder
                .anIdpSsoDescriptor()
                .addKeyDescriptor(keyDescriptor)
                .build();
        try {
            return EntityDescriptorBuilder
                    .anEntityDescriptor()
                    .withEntityId(entityID)
                    .withIdpSsoDescriptor(idpssoDescriptor)
                    .withSignature(signature)
                    .build();
        } catch (MarshallingException | SignatureException e) {
            throw Throwables.propagate(e);
        }
    }

    public static String createMetadata(EntityDescriptor entityDescriptor) {
        Element element = entityDescriptorXmlObjectToElementTransformer.apply(entityDescriptor);
        return XmlUtils.writeToString(element);
    }

    private static Signature createSignature(String publicCert, String privateKey) {
        TestCredentialFactory testCredentialFactory = new TestCredentialFactory(publicCert, privateKey);
        Credential credential = testCredentialFactory.getSigningCredential();
        return SignatureBuilder
                .aSignature()
                .withSigningCredential(credential)
                .withX509Data(publicCert)
                .build();
    }
}
