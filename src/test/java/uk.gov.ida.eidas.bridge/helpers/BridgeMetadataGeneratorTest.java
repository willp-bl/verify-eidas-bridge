package uk.gov.ida.eidas.bridge.helpers;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.common.shared.security.Certificate;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.metadata.transformers.KeyDescriptorsUnmarshaller;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class BridgeMetadataGeneratorTest {

    private KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller;
    private Certificate signingCertificate = new Certificate("entityId", TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT, Certificate.KeyUse.Signing);

    @Before
    public void bootStrapOpenSaml() {
        EidasSamlBootstrap.bootstrap();
        keyDescriptorsUnmarshaller = new KeyDescriptorsUnmarshaller(new OpenSamlXmlObjectFactory());
    }

    @Test
    public void shouldGenerateMetadata() throws SignatureException, MarshallingException {
        BridgeMetadataGenerator bridgeMetadataGenerator = new BridgeMetadataGenerator(
            "entityId",
            keyDescriptorsUnmarshaller,
            signingCertificate);

        EntitiesDescriptor entitiesDescriptor = bridgeMetadataGenerator.generateMetadata();
        assertEquals("Should have an entitiesDescriptor", "entitiesDescriptor", entitiesDescriptor.getID());
        assertNotNull("Should have a ValidUntil attribute", entitiesDescriptor.getValidUntil());
        EntityDescriptor entityDescriptor = entitiesDescriptor.getEntityDescriptors().get(0);
        assertNotNull("Should have bridge entity descriptor", entityDescriptor);
        assertEquals("Should have an entityDescriptor ID", "bridgeEntityDescriptor", entityDescriptor.getID());

        SPSSODescriptor spSsoDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        assertNotNull("Should have an SPSSODescriptor", spSsoDescriptor);
        List<KeyDescriptor> keyDescriptors = spSsoDescriptor.getKeyDescriptors();
        assertTrue("Should have at least one key descriptor", keyDescriptors.size() > 0);

        KeyDescriptor keyDescriptor = keyDescriptors.get(0);
        assertEquals("Should have the key use signing", UsageType.SIGNING, keyDescriptor.getUse());
        X509Data x509Data = keyDescriptor.getKeyInfo().getX509Datas().get(0);
        X509Certificate certificate = x509Data.getX509Certificates().get(0);
        assertNotNull("Should have a certificate", certificate);
    }
}
