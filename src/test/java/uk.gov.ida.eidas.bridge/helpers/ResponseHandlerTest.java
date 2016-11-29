package uk.gov.ida.eidas.bridge.helpers;


import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import uk.gov.ida.saml.core.api.CoreTransformersFactory;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.core.test.builders.IssuerBuilder;
import uk.gov.ida.saml.core.test.builders.ResponseBuilder;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.deserializers.validators.SizeValidator;
import uk.gov.ida.saml.security.SignatureValidator;

import javax.xml.namespace.QName;

import static junit.framework.TestCase.assertNotNull;
import static uk.gov.ida.eidas.bridge.testhelpers.ResponseStringBuilder.buildString;
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
        ResponseHandler responseHandler = new ResponseHandler(stringToResponse, signatureValidator(true), EIDAS_ENTITY_ID);

        IssuerBuilder issuerBuilder = IssuerBuilder.anIssuer().withIssuerId(EIDAS_ENTITY_ID);
        ResponseBuilder responseBuilder = aResponse().withIssuer(issuerBuilder.build());
        String responseString = buildString(responseBuilder);
        assertNotNull(responseHandler.handleResponse(responseString));
    }

    @Test(expected = SecurityException.class)
    public void shouldReturnResponseWhenSignatureInvalid() throws Exception {
        ResponseHandler responseHandler = new ResponseHandler(stringToResponse, signatureValidator(false), EIDAS_ENTITY_ID);

        IssuerBuilder issuerBuilder = IssuerBuilder.anIssuer().withIssuerId(EIDAS_ENTITY_ID);
        ResponseBuilder responseBuilder = aResponse().withIssuer(issuerBuilder.build());
        Credential signingCredential = new TestCredentialFactory(TestCertificateStrings.UNCHAINED_PUBLIC_CERT, TestCertificateStrings.UNCHAINED_PRIVATE_KEY).getSigningCredential();
        responseBuilder.withSigningCredential(signingCredential);
        String responseString = buildString(responseBuilder);
        assertNotNull(responseHandler.handleResponse(responseString));
    }

    @Test(expected = SecurityException.class)
    public void shouldThrowSecurityExceptionWhenIssuerIsNotEidas() throws Exception {
        ResponseHandler responseHandler = new ResponseHandler(stringToResponse, signatureValidator(true), EIDAS_ENTITY_ID);
        IssuerBuilder issuerBuilder = IssuerBuilder.anIssuer().withIssuerId("not-the-" + EIDAS_ENTITY_ID);
        responseHandler.handleResponse(buildString(aResponse().withIssuer(issuerBuilder.build())));
    }

    private SignatureValidator signatureValidator(final boolean validationShouldSucceed) {
        return new SignatureValidator() {
            @Override
            protected boolean additionalValidations(SignableSAMLObject signableSAMLObject, String entityId, QName role) throws SecurityException {
                return validationShouldSucceed;
            }
        };
    }
}
