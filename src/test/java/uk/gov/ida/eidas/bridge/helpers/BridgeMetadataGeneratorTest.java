package uk.gov.ida.eidas.bridge.helpers;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.eidas.bridge.factories.BridgeMetadataFactory;
import uk.gov.ida.eidas.bridge.resources.EidasResponseResource;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class BridgeMetadataGeneratorTest {

    public static final String HOSTNAME = "http://bridge.hostname";
    private BridgeMetadataGenerator bridgeMetadataGenerator;

    @Before
    public void bootStrapOpenSaml() throws UnrecoverableKeyException, CertificateEncodingException, NoSuchAlgorithmException, KeyStoreException {
        EidasSamlBootstrap.bootstrap();
        Certificate signingCertificate =  new X509CertificateFactory().createCertificate(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT);
        Certificate encryptingCertificate =  new X509CertificateFactory().createCertificate(TestCertificateStrings.TEST_PUBLIC_CERT);
        Credential credential = new TestCredentialFactory(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT, TestCertificateStrings.METADATA_SIGNING_A_PRIVATE_KEY).getSigningCredential();
        bridgeMetadataGenerator = new BridgeMetadataFactory(HOSTNAME, signingCertificate, encryptingCertificate, credential.getPrivateKey(), "entityId").getBridgeMetadataGenerator();
    }

    @Test
    public void shouldGenerateMetadataEntitiesDescriptor() throws SignatureException, MarshallingException, SecurityException {
        EntitiesDescriptor entitiesDescriptor = bridgeMetadataGenerator.generateMetadata();
        assertEquals("Should have an entitiesDescriptor", "entitiesDescriptor", entitiesDescriptor.getID());
        assertNotNull("Should have a ValidUntil attribute", entitiesDescriptor.getValidUntil());
        EntityDescriptor entityDescriptor = entitiesDescriptor.getEntityDescriptors().get(0);
        assertNotNull("Should have bridge entity descriptor", entityDescriptor);
        assertEquals("Should have an entityDescriptor ID", "bridgeEntityDescriptor", entityDescriptor.getID());
    }

    @Test
    public void shouldGenerateMetadataSPSSODescriptor() throws SignatureException, MarshallingException, SecurityException {
        EntitiesDescriptor entitiesDescriptor = bridgeMetadataGenerator.generateMetadata();
        EntityDescriptor entityDescriptor = entitiesDescriptor.getEntityDescriptors().get(0);

        SPSSODescriptor spSsoDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        assertNotNull("Should have an SPSSODescriptor", spSsoDescriptor);
        List<KeyDescriptor> keyDescriptors = spSsoDescriptor.getKeyDescriptors();
        assertTrue("Should have at least one key descriptor", keyDescriptors.size() > 0);
        List<AssertionConsumerService> assertionConsumerServices = spSsoDescriptor.getAssertionConsumerServices();
        assertTrue("Should have at least one assertion consumer service", assertionConsumerServices.size() > 0);
        AssertionConsumerService assertionConsumerService = assertionConsumerServices.get(0);
        assertEquals(HOSTNAME + EidasResponseResource.ASSERTION_CONSUMER_PATH, assertionConsumerService.getLocation());
        assertEquals(SAMLConstants.SAML2_POST_BINDING_URI, assertionConsumerService.getBinding());
    }

    @Test
    public void shouldGenerateMetadataSigningKeyDescriptor() throws SignatureException, MarshallingException, SecurityException {
        EntitiesDescriptor entitiesDescriptor = bridgeMetadataGenerator.generateMetadata();
        EntityDescriptor entityDescriptor = entitiesDescriptor.getEntityDescriptors().get(0);

        SPSSODescriptor spSsoDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        List<KeyDescriptor> keyDescriptors = spSsoDescriptor.getKeyDescriptors();
        KeyDescriptor keyDescriptor = keyDescriptors.get(0);
        assertEquals("Should have the key use signing", UsageType.SIGNING, keyDescriptor.getUse());
        X509Data x509Data = keyDescriptor.getKeyInfo().getX509Datas().get(0);
        X509Certificate theCertificate = x509Data.getX509Certificates().get(0);
        assertNotNull("Should have a certificate", theCertificate);
    }

    @Test
    public void shouldGenerateMetadataEncryptionKeyDescriptor() throws SignatureException, MarshallingException, SecurityException {
        EntitiesDescriptor entitiesDescriptor = bridgeMetadataGenerator.generateMetadata();
        EntityDescriptor entityDescriptor = entitiesDescriptor.getEntityDescriptors().get(0);

        SPSSODescriptor spSsoDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        List<KeyDescriptor> keyDescriptors = spSsoDescriptor.getKeyDescriptors();
        KeyDescriptor keyDescriptor = keyDescriptors.get(1);
        assertEquals("Should have the key use encryption", UsageType.ENCRYPTION, keyDescriptor.getUse());
        X509Data x509Data = keyDescriptor.getKeyInfo().getX509Datas().get(0);
        X509Certificate theCertificate = x509Data.getX509Certificates().get(0);
        assertNotNull("Should have a certificate", theCertificate);
    }


    @Test
    public void shouldSignMetadata() throws SignatureException, MarshallingException, SecurityException {
        EntitiesDescriptor entitiesDescriptor = bridgeMetadataGenerator.generateMetadata();
        Signature entitiesDescriptorSignature = entitiesDescriptor.getSignature();
        assertNotNull("Should have a signature", entitiesDescriptorSignature);
        assertNotNull("Should have key info", entitiesDescriptorSignature.getKeyInfo());

        EntityDescriptor entityDescriptor = entitiesDescriptor.getEntityDescriptors().get(0);
        Signature entityDescriptorSignature = entityDescriptor.getSignature();
        assertNotNull("Should have a signature", entityDescriptorSignature);
        assertNotNull("Should have key info", entityDescriptorSignature.getKeyInfo());

        SPSSODescriptor spSsoDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        Signature spSsoDescriptorSignature = spSsoDescriptor.getSignature();
        assertNotNull("Should have a signature", spSsoDescriptorSignature);
        assertNotNull("Should have key info", spSsoDescriptorSignature.getKeyInfo());

    }
}
