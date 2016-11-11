package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.metadata.MetadataConfiguration;
import uk.gov.ida.saml.security.SignatureValidator;

public class AuthnRequestHandler {
    private final MetadataConfiguration configuration;
    private final SignatureValidator metadataBackedSignatureValidator;
    private final StringToOpenSamlObjectTransformer<AuthnRequest> stringToAuthnRequest;

    public AuthnRequestHandler(
        MetadataConfiguration configuration,
        SignatureValidator metadataBackedSignatureValidator,
        StringToOpenSamlObjectTransformer<AuthnRequest> stringToAuthnRequest) {
        this.configuration = configuration;
        this.metadataBackedSignatureValidator = metadataBackedSignatureValidator;
        this.stringToAuthnRequest = stringToAuthnRequest;
    }

    public AuthnRequest handleAuthnRequest(String base64AuthnRequest) throws SecurityException, SignatureException {
        AuthnRequest authnRequest = stringToAuthnRequest.apply(base64AuthnRequest);

        String expectedEntityId = configuration.getExpectedEntityId();
        String actualIssuer = authnRequest.getIssuer().getValue();
        if(!expectedEntityId.equals(actualIssuer)) {
            throw new SecurityException("Authn request issuer (" + actualIssuer + ") didn't match expected issuer (" + expectedEntityId + ")");
        }
        expectedEntityId.equals(actualIssuer);
        boolean validSignature = metadataBackedSignatureValidator.validate(
            authnRequest,
            expectedEntityId,
            SPSSODescriptor.DEFAULT_ELEMENT_NAME
        );

        if (!validSignature) {
            throw new SecurityException("Could not validate signature on AuthnRequest");
        }

        return authnRequest;
    }
}
