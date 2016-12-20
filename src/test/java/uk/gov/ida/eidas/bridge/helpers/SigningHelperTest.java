package uk.gov.ida.eidas.bridge.helpers;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.eidas.bridge.testhelpers.TestSignatureValidator;
import uk.gov.ida.saml.core.test.builders.AssertionBuilder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static uk.gov.ida.eidas.bridge.testhelpers.SigningHelperBuilder.aSigningHelper;

public class SigningHelperTest {

    private SigningHelper signingHelper;

    @Before
    public void before() {
        EidasSamlBootstrap.bootstrap();
        signingHelper = aSigningHelper().build();
    }

    @Test
    public void shouldSignSamlObjects() throws MarshallingException, SecurityException, SignatureException {
        Assertion assertion = new AssertionBuilder().buildUnencrypted();
        signingHelper.sign(assertion);
        Signature signature = assertion.getSignature();
        assertNotNull(signature);
        assertTrue(TestSignatureValidator.getSignatureValidator().validate(assertion, null, SPSSODescriptor.DEFAULT_ELEMENT_NAME));
        assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, signature.getSignatureAlgorithm());
        assertNotNull(signature.getKeyInfo());
    }
}
