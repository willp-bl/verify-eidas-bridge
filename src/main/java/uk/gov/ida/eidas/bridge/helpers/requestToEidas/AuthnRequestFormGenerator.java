package uk.gov.ida.eidas.bridge.helpers.requestToEidas;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.eidas.bridge.SamlRequest;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

public class AuthnRequestFormGenerator {
    private final EidasAuthnRequestGenerator eidasAuthnRequestGenerator;
    private final XmlObjectToBase64EncodedStringTransformer xmlObjectToBase64EncodedStringTransformer;

    public AuthnRequestFormGenerator(
            EidasAuthnRequestGenerator eidasAuthnRequestGenerator,
            XmlObjectToBase64EncodedStringTransformer xmlObjectToBase64EncodedStringTransformer) {
        this.eidasAuthnRequestGenerator = eidasAuthnRequestGenerator;
        this.xmlObjectToBase64EncodedStringTransformer = xmlObjectToBase64EncodedStringTransformer;
    }

    public SamlRequest generateAuthnRequestForm(String authnRequestId, String destinationEntityId) throws MarshallingException, SignatureException, SecurityException {
        AuthnRequest eidasAuthnRequest = eidasAuthnRequestGenerator.generateAuthnRequest(authnRequestId, destinationEntityId);
        return new SamlRequest(
            xmlObjectToBase64EncodedStringTransformer.apply(eidasAuthnRequest),
                eidasAuthnRequest.getDestination()
        );
    }
}
