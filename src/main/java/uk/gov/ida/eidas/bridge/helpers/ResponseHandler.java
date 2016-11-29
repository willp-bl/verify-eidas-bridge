package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.security.SignatureValidator;

public class ResponseHandler {
    private final StringToOpenSamlObjectTransformer<Response> stringToResponse;
    private final SignatureValidator signatureValidator;
    private final String eidasEntityId;


    public ResponseHandler(StringToOpenSamlObjectTransformer<Response> stringToResponse,
                           SignatureValidator signatureValidator,
                           String eidasEntityId) {
        this.stringToResponse = stringToResponse;
        this.signatureValidator = signatureValidator;
        this.eidasEntityId = eidasEntityId;
    }

    public Response handleResponse(String base64EncodedResponse) throws SignatureException, SecurityException {
        Response response = this.stringToResponse.apply(base64EncodedResponse);

        String actualIssuer = response.getIssuer().getValue();
        if(!this.eidasEntityId.equals(actualIssuer)) {
            throw new SecurityException("Response issuer (" + actualIssuer + ") didn't match expected issuer (" + this.eidasEntityId + ")");
        }
        boolean validSignature = signatureValidator.validate(
            response,
            eidasEntityId,
            IDPSSODescriptor.DEFAULT_ELEMENT_NAME
        );

        if (!validSignature) {
            throw new SecurityException("Could not validate signature on Response");
        }

        return response;
    }
}
