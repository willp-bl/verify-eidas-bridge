package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.eidas.bridge.domain.EidasSamlResponse;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.security.AssertionDecrypter;
import uk.gov.ida.saml.security.SamlAssertionsSignatureValidator;
import uk.gov.ida.saml.security.validators.ValidatedAssertions;
import uk.gov.ida.saml.security.validators.ValidatedResponse;
import uk.gov.ida.saml.security.validators.signature.SamlResponseSignatureValidator;

import java.util.List;

public class ResponseHandler {
    private final StringToOpenSamlObjectTransformer<Response> stringToResponse;
    private final String eidasEntityId;
    private final SamlResponseSignatureValidator samlResponseSignatureValidator;
    private final AssertionDecrypter assertionDecrypter;
    private final SamlAssertionsSignatureValidator samlAssertionsSignatureValidator;


    public ResponseHandler(StringToOpenSamlObjectTransformer<Response> stringToResponse,
                           String eidasEntityId,
                           SamlResponseSignatureValidator samlResponseSignatureValidator,
                           AssertionDecrypter assertionDecrypter,
                           SamlAssertionsSignatureValidator samlAssertionsSignatureValidator) {
        this.stringToResponse = stringToResponse;
        this.eidasEntityId = eidasEntityId;
        this.samlResponseSignatureValidator = samlResponseSignatureValidator;
        this.assertionDecrypter = assertionDecrypter;
        this.samlAssertionsSignatureValidator = samlAssertionsSignatureValidator;
    }

    public EidasSamlResponse handleResponse(String base64EncodedResponse) throws SignatureException, SecurityException {
        Response response = this.stringToResponse.apply(base64EncodedResponse);

        String actualIssuer = response.getIssuer().getValue();
        if(!this.eidasEntityId.equals(actualIssuer)) {
            throw new SecurityException("Response issuer (" + actualIssuer + ") didn't match expected issuer (" + this.eidasEntityId + ")");
        }

        ValidatedResponse validatedResponse = samlResponseSignatureValidator.validate(response, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        List<Assertion> decryptedAssertions = assertionDecrypter.decryptAssertions(validatedResponse);
        ValidatedAssertions validatedAssertions = samlAssertionsSignatureValidator.validate(decryptedAssertions, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

        return new EidasSamlResponse(validatedAssertions);
    }
}
