package uk.gov.ida.eidas.bridge.helpers;


import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import uk.gov.ida.common.shared.security.PrivateKeyFactory;
import uk.gov.ida.common.shared.security.PublicKeyFactory;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.eidas.bridge.domain.EidasSamlResponse;
import uk.gov.ida.saml.core.api.CoreTransformersFactory;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.core.test.builders.IssuerBuilder;
import uk.gov.ida.saml.core.test.builders.ResponseBuilder;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.deserializers.validators.SizeValidator;
import uk.gov.ida.saml.security.AssertionDecrypter;
import uk.gov.ida.saml.security.DecrypterFactory;
import uk.gov.ida.saml.security.KeyStore;
import uk.gov.ida.saml.security.KeyStoreCredentialRetriever;
import uk.gov.ida.saml.security.SamlAssertionsSignatureValidator;
import uk.gov.ida.saml.security.SamlMessageSignatureValidator;
import uk.gov.ida.saml.security.SignatureValidator;
import uk.gov.ida.saml.security.exception.SamlFailedToDecryptException;
import uk.gov.ida.saml.security.validators.encryptedelementtype.EncryptionAlgorithmValidator;
import uk.gov.ida.saml.security.validators.signature.SamlResponseSignatureValidator;

import javax.xml.namespace.QName;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static uk.gov.ida.eidas.bridge.testhelpers.ResponseStringBuilder.buildString;
import static uk.gov.ida.saml.core.test.builders.AssertionBuilder.anAssertion;
import static uk.gov.ida.saml.core.test.builders.ResponseBuilder.aResponse;

public class ResponseHandlerTest {
    public static final String EIDAS_ENTITY_ID = "an-entity-id";
    private StringToOpenSamlObjectTransformer<Response> stringToResponse =
        new CoreTransformersFactory().getStringtoOpenSamlObjectTransformer((SizeValidator) input -> { });

    @Before
    public void bootStrapOpenSaml() {
        EidasSamlBootstrap.bootstrap();
    }

    @Test
    public void shouldReturnResponseWhenSignatureValid() throws Exception {
        ResponseHandler responseHandler = aResponseHandler().build();

        Issuer issuer = IssuerBuilder.anIssuer().withIssuerId(EIDAS_ENTITY_ID).build();
        ResponseBuilder responseBuilder = getResponseBuilder(issuer);
        String responseString = buildString(responseBuilder);
        assertNotNull(responseHandler.handleResponse(responseString, "default-response-id"));
    }

    @Test(expected = SamlTransformationErrorException.class)
    public void shouldReturnResponseWhenSignatureInvalid() throws Exception {
        ResponseHandler responseHandler = aResponseHandler().shouldFailMessageSignatureValidation().build();

        Issuer issuer = IssuerBuilder.anIssuer().withIssuerId(EIDAS_ENTITY_ID).build();
        ResponseBuilder responseBuilder = getResponseBuilder(issuer);
        Credential signingCredential = new TestCredentialFactory(TestCertificateStrings.UNCHAINED_PUBLIC_CERT, TestCertificateStrings.UNCHAINED_PRIVATE_KEY).getSigningCredential();
        responseBuilder.withSigningCredential(signingCredential);
        String responseString = buildString(responseBuilder);
        responseHandler.handleResponse(responseString, "default-response-id");
    }

    @Test
    public void shouldDecryptAssertions() throws Exception {
        ResponseHandler responseHandler = aResponseHandler().build();

        Issuer issuer = IssuerBuilder.anIssuer().withIssuerId(EIDAS_ENTITY_ID).build();
        ResponseBuilder responseBuilder = getResponseBuilder(issuer);
        String responseString = buildString(responseBuilder);
        EidasSamlResponse response = responseHandler.handleResponse(responseString, "default-response-id");
        assertNotNull(response);

        assertTrue("Should have at least one assertion that's decrypted", response.getAssertions().size() > 0);
    }

    @Test(expected = SamlFailedToDecryptException.class)
    public void shouldThrowErrorWhenAssertionsEncryptedUsingIncorrectEncryptionCert() throws Exception {
        ResponseHandler responseHandler = aResponseHandler().build();

        TestCredentialFactory testCredentialFactory = new TestCredentialFactory(TestCertificateStrings.UNCHAINED_PUBLIC_CERT, TestCertificateStrings.UNCHAINED_PRIVATE_KEY);
        Issuer issuer = IssuerBuilder.anIssuer().withIssuerId(EIDAS_ENTITY_ID).build();
        ResponseBuilder responseBuilder = getResponseBuilder(issuer);
        responseBuilder.addEncryptedAssertion(anAssertion().buildWithEncrypterCredential(testCredentialFactory.getEncryptingCredential()));
        String responseString = buildString(responseBuilder);
        EidasSamlResponse response = responseHandler.handleResponse(responseString, "default-response-id");
        assertNotNull(response);

        assertTrue("Should have at least one assertion that's decrypted", response.getAssertions().size() > 0);
    }

    @Test(expected = SamlTransformationErrorException.class)
    public void shouldThrowErrorWhenAssertionsFailSignatureValidation() throws Exception {
        ResponseHandler responseHandler = aResponseHandler().shouldFailAssertionSignatureValidation().build();

        TestCredentialFactory testCredentialFactory2 = new TestCredentialFactory(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT, TestCertificateStrings.HUB_TEST_PRIVATE_ENCRYPTION_KEY);
        Issuer issuer = IssuerBuilder.anIssuer().withIssuerId(EIDAS_ENTITY_ID).build();
        ResponseBuilder responseBuilder = getResponseBuilder(issuer);

        responseBuilder.addEncryptedAssertion(anAssertion().buildWithEncrypterCredential(testCredentialFactory2.getEncryptingCredential()));
        String responseString = buildString(responseBuilder);
        EidasSamlResponse response = responseHandler.handleResponse(responseString, "default-response-id");
        assertNotNull(response);

        assertTrue("Should have at least one assertion that's decrypted", response.getAssertions().size() > 0);
    }

    @Test(expected = SecurityException.class)
    public void shouldThrowSecurityExceptionWhenIssuerIsNotEidas() throws Exception {
        ResponseHandler responseHandler = aResponseHandler().build();
        Issuer issuer = IssuerBuilder.anIssuer().withIssuerId("not-the-" + EIDAS_ENTITY_ID).build();
        ResponseBuilder responseBuilder = getResponseBuilder(issuer);
        responseHandler.handleResponse(buildString(responseBuilder), "default-response-id");
    }

    @Test(expected = SecurityException.class)
    public void shouldThrowSecurityExceptionWhenIdDoesNotMatchExpectedValue() throws Exception {
        ResponseHandler responseHandler = aResponseHandler().build();

        Issuer issuer = IssuerBuilder.anIssuer().withIssuerId(EIDAS_ENTITY_ID).build();
        ResponseBuilder responseBuilder = getResponseBuilder(issuer);
        String responseString = buildString(responseBuilder);
        assertNotNull(responseHandler.handleResponse(responseString, "NOT-default-response-id"));
    }

    private SignatureValidator signatureValidator(final boolean validationShouldSucceed) {
        return new SignatureValidator() {
            @Override
            protected boolean additionalValidations(SignableSAMLObject signableSAMLObject, String entityId, QName role) throws SecurityException {
                return validationShouldSucceed;
            }
        };
    }

    private ResponseBuilder getResponseBuilder(Issuer issuer) {
        TestCredentialFactory testCredentialFactory = new TestCredentialFactory(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT, TestCertificateStrings.HUB_TEST_PRIVATE_ENCRYPTION_KEY);
        return aResponse().withIssuer(issuer).addEncryptedAssertion(anAssertion().buildWithEncrypterCredential(testCredentialFactory.getEncryptingCredential()));
    }

    private static KeyStore getKeyStore() throws Base64DecodingException {
        List<KeyPair> encryptionKeyPairs = new ArrayList<>();
        PublicKeyFactory publicKeyFactory = new PublicKeyFactory(new X509CertificateFactory());
        PrivateKeyFactory privateKeyFactory = new PrivateKeyFactory();
        PublicKey encryptionPublicKey = publicKeyFactory.createPublicKey(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT);
        PrivateKey encryptionPrivateKey = privateKeyFactory.createPrivateKey(Base64.decode(TestCertificateStrings.HUB_TEST_PRIVATE_ENCRYPTION_KEY.getBytes()));
        encryptionKeyPairs.add(new KeyPair(encryptionPublicKey, encryptionPrivateKey));
        PublicKey publicSigningKey = publicKeyFactory.createPublicKey(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT);
        PrivateKey privateSigningKey = privateKeyFactory.createPrivateKey(Base64.decode(TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY.getBytes()));
        KeyPair signingKeyPair = new KeyPair(publicSigningKey, privateSigningKey);

        return new KeyStore(signingKeyPair, encryptionKeyPairs);
    }

    private ResponseHandlerBuilder aResponseHandler() {
        return new ResponseHandlerBuilder();
    }

    class ResponseHandlerBuilder {
        private boolean shouldPassMessageSignatureValidation = true;
        private boolean shouldPassAssertionSignatureValidation = true;

        public ResponseHandlerBuilder shouldFailMessageSignatureValidation() {
            this.shouldPassMessageSignatureValidation = false;
            return this;
        }
        public ResponseHandlerBuilder shouldFailAssertionSignatureValidation() {
            this.shouldPassAssertionSignatureValidation = false;
            return this;
        }
        public ResponseHandler build() throws Base64DecodingException {
            SignatureValidator signatureValidator = signatureValidator(this.shouldPassMessageSignatureValidation);
            SamlMessageSignatureValidator samlMessageSignatureValidator = new SamlMessageSignatureValidator(signatureValidator);
            KeyStore samlSecurityKeyStore = getKeyStore();
            SamlResponseSignatureValidator samlResponseSignatureValidator = new SamlResponseSignatureValidator(samlMessageSignatureValidator);
            AssertionDecrypter assertionDecrypter = new AssertionDecrypter(new KeyStoreCredentialRetriever(samlSecurityKeyStore), new EncryptionAlgorithmValidator(), new DecrypterFactory());


            SamlAssertionsSignatureValidator samlAssertionsSignatureValidator = new SamlAssertionsSignatureValidator(new SamlMessageSignatureValidator(signatureValidator(this.shouldPassAssertionSignatureValidation)));

            return new ResponseHandler(stringToResponse, EIDAS_ENTITY_ID, samlResponseSignatureValidator, assertionDecrypter, samlAssertionsSignatureValidator);
        }
    }
}
