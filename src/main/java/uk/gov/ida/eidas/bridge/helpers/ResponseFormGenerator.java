package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.eidas.bridge.SamlResponse;
import uk.gov.ida.saml.core.transformers.outbound.ResponseToSignedStringTransformer;

public class ResponseFormGenerator {
    private final VerifyResponseGenerator verifyResponseGenerator;
    private final AssertionConsumerServiceLocator assertionConsumerServiceLocator;
    private final String verifyEntityId;
    private final ResponseToSignedStringTransformer responseToSignedStringTransformer;

    public ResponseFormGenerator(VerifyResponseGenerator verifyResponseGenerator, AssertionConsumerServiceLocator assertionConsumerServiceLocator, String verifyEntityId, ResponseToSignedStringTransformer responseToSignedStringTransformer) {
        this.verifyResponseGenerator = verifyResponseGenerator;
        this.assertionConsumerServiceLocator = assertionConsumerServiceLocator;
        this.verifyEntityId = verifyEntityId;
        this.responseToSignedStringTransformer = responseToSignedStringTransformer;
    }

    public SamlResponse generateResponseForm(String inResponseTo) throws MarshallingException, SignatureException, SecurityException {
        String assertionConsumerServiceLocation = assertionConsumerServiceLocator.getAssertionConsumerServiceLocation(verifyEntityId);
        Response response = verifyResponseGenerator.generateResponse(assertionConsumerServiceLocation, inResponseTo, null);
        return new SamlResponse(
            responseToSignedStringTransformer.apply(response),
            assertionConsumerServiceLocation
        );
    }
}
