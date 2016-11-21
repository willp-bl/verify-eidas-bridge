package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.eidas.bridge.SamlRequest;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

public class AuthnRequestFormGenerator {
    private final EidasAuthnRequestGenerator eidasAuthnRequestGenerator;
    private final SingleSignOnServiceLocator signOnServiceLocator;
    private final XmlObjectToBase64EncodedStringTransformer xmlObjectToBase64EncodedStringTransformer;
    private final String eidasConnectorNodeEntityId;

    public AuthnRequestFormGenerator(
        EidasAuthnRequestGenerator eidasAuthnRequestGenerator,
        SingleSignOnServiceLocator signOnServiceLocator,
        XmlObjectToBase64EncodedStringTransformer xmlObjectToBase64EncodedStringTransformer,
        String eidasConnectorNodeEntityId) {
        this.eidasAuthnRequestGenerator = eidasAuthnRequestGenerator;
        this.signOnServiceLocator = signOnServiceLocator;
        this.xmlObjectToBase64EncodedStringTransformer = xmlObjectToBase64EncodedStringTransformer;
        this.eidasConnectorNodeEntityId = eidasConnectorNodeEntityId;
    }

    public SamlRequest generateAuthnRequestForm(String authnRequestId) throws MarshallingException, SignatureException {
        AuthnRequest eidasAuthnRequest = eidasAuthnRequestGenerator.generateAuthnRequest(authnRequestId);
        return new SamlRequest(
            xmlObjectToBase64EncodedStringTransformer.apply(eidasAuthnRequest),
            signOnServiceLocator.getSignOnUrl(eidasConnectorNodeEntityId)
        );
    }
}
