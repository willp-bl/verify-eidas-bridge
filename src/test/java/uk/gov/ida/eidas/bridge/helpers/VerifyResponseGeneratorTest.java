package uk.gov.ida.eidas.bridge.helpers;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.eidas.bridge.testhelpers.TestSignatureValidator;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.domain.Gender;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.core.transformers.outbound.decorators.SamlResponseAssertionEncrypter;
import uk.gov.ida.saml.hub.factories.AttributeFactory_1_1;
import uk.gov.ida.saml.security.EncrypterFactory;
import uk.gov.ida.saml.security.EncryptionCredentialFactory;

import java.security.PublicKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static uk.gov.ida.eidas.bridge.testhelpers.SigningHelperBuilder.aSigningHelper;

public class VerifyResponseGeneratorTest {

    public static final String IN_RESPONSE_TO = "responseTo";
    private final String BRIDGE_ENTITY_ID = "bridge-entity-id";
    private final String VERIFY_ENTITY_ID = "verify-entity-id";
    private static final String IP_ADDRESS = "127.0.0.1";

    private final String assertionConsumerServiceLocation = "http://some-destination";
    private EidasIdentityAssertion eidasIdentityAssertion;
    private VerifyResponseGenerator verifyResponseGenerator;

    @Before
    public void before() {
        EidasSamlBootstrap.bootstrap();
        eidasIdentityAssertion = new EidasIdentityAssertion("Ab", "ba", "holborn", Gender.FEMALE, new DateTime(1965, 1, 1, 0, 0));
        OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
        AssertionSubjectGenerator assertionSubjectGenerator = new AssertionSubjectGenerator(VERIFY_ENTITY_ID, openSamlXmlObjectFactory);
        AttributeFactory_1_1 attributeFactory = new AttributeFactory_1_1(openSamlXmlObjectFactory);
        AuthnStatementAssertionGenerator authnStatementAssertionGenerator = new AuthnStatementAssertionGenerator(BRIDGE_ENTITY_ID, openSamlXmlObjectFactory, attributeFactory, assertionSubjectGenerator, aSigningHelper().build());
        SigningHelper signingHelper = aSigningHelper().build();
        MatchingDatasetAssertionGenerator matchingDatasetAssertionGenerator = new MatchingDatasetAssertionGenerator(BRIDGE_ENTITY_ID, openSamlXmlObjectFactory, attributeFactory, assertionSubjectGenerator, signingHelper);
        PublicKey encryptionPublicKey = new TestCredentialFactory(TestCertificateStrings.TEST_PUBLIC_CERT, TestCertificateStrings.TEST_PRIVATE_KEY).getEncryptingCredential().getPublicKey();
        EncryptionCredentialFactory encryptionCredentialFactory = new EncryptionCredentialFactory(keyStore -> encryptionPublicKey);
        SamlResponseAssertionEncrypter samlResponseAssertionEncrypter = new SamlResponseAssertionEncrypter(encryptionCredentialFactory, new EncrypterFactory(), requestId -> VERIFY_ENTITY_ID);
        this.verifyResponseGenerator = new VerifyResponseGenerator(BRIDGE_ENTITY_ID, matchingDatasetAssertionGenerator, authnStatementAssertionGenerator, samlResponseAssertionEncrypter, signingHelper);
    }


    @Test
    public void shouldGenerateAResponse() throws MarshallingException, SecurityException, SignatureException {
        Response response = verifyResponseGenerator.generateResponse(assertionConsumerServiceLocation, IN_RESPONSE_TO, IP_ADDRESS, eidasIdentityAssertion);
        assertNotNull(response);

        assertEquals(assertionConsumerServiceLocation, response.getDestination());
        assertNotNull(response.getID());
        assertNotNull(response.getInResponseTo());
        assertNotNull(response.getIssueInstant());
    }

    @Test
    public void shouldGenerateAResponseWithIssue() throws MarshallingException, SecurityException, SignatureException {
        Response response = verifyResponseGenerator.generateResponse(assertionConsumerServiceLocation, IN_RESPONSE_TO, IP_ADDRESS, eidasIdentityAssertion);
        assertNotNull(response);

        Issuer issuer = response.getIssuer();
        assertNotNull(issuer);
        assertEquals(NameIDType.ENTITY, issuer.getFormat());
        assertEquals(BRIDGE_ENTITY_ID, issuer.getValue());
    }

    @Test
    public void shouldGenerateAResponseWithStatus() throws MarshallingException, SecurityException, SignatureException {
        Response response = verifyResponseGenerator.generateResponse(assertionConsumerServiceLocation, IN_RESPONSE_TO, IP_ADDRESS, eidasIdentityAssertion);
        assertNotNull(response);

        Status status = response.getStatus();
        assertNotNull(status);
        StatusCode statusCode = status.getStatusCode();
        assertNotNull(statusCode);
        assertEquals(StatusCode.SUCCESS, statusCode.getValue());
    }

    @Test
    public void shouldGenerateAResponseWithEncryptedAssertions() throws MarshallingException, SecurityException, SignatureException {
        Response response = verifyResponseGenerator.generateResponse(assertionConsumerServiceLocation, IN_RESPONSE_TO, IP_ADDRESS, eidasIdentityAssertion);
        assertNotNull(response);

        assertTrue("There should be two assertions (Matching Dataset and AuthnStatement)", response.getEncryptedAssertions().size() == 2);
    }

    @Test
    public void shouldSignTheResponse() throws MarshallingException, SecurityException, SignatureException {
        Response response = verifyResponseGenerator.generateResponse(assertionConsumerServiceLocation, IN_RESPONSE_TO, IP_ADDRESS, eidasIdentityAssertion);
        assertNotNull(response);

        Signature signature = response.getSignature();
        assertNotNull(signature);
        assertTrue(TestSignatureValidator.getSignatureValidator().validate(response, null, IDPSSODescriptor.DEFAULT_ELEMENT_NAME));
        assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, signature.getSignatureAlgorithm());
        assertNotNull(signature.getKeyInfo());
    }
}
