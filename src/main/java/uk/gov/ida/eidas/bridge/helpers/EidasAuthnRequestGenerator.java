package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.saml.saml2.core.AuthnRequest;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;

public class EidasAuthnRequestGenerator {
    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();

    public AuthnRequest generateAuthnRequest(String authnReqeustId) {
        AuthnRequest eidaAuthnRequest = openSamlXmlObjectFactory.createAuthnRequest();
        eidaAuthnRequest.setID(authnReqeustId);
        return eidaAuthnRequest;
    }
}
