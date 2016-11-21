package uk.gov.ida.eidas.bridge.resources;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.eidas.bridge.helpers.AuthnRequestHandler;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/SAML2/SSO/POST")
@Produces(MediaType.APPLICATION_JSON)
public class VerifyAuthnRequestResource {

    private static final Logger LOG = LoggerFactory.getLogger(VerifyAuthnRequestResource.class);

    private AuthnRequestHandler authnRequestHandler;

    public VerifyAuthnRequestResource(AuthnRequestHandler authnRequestHandler) {
        this.authnRequestHandler = authnRequestHandler;
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response receiveAuthnRequest(@FormParam("SAMLRequest") String authnRequestStr) {
        AuthnRequest authnRequest;
        try {
            authnRequest = authnRequestHandler.handleAuthnRequest(authnRequestStr);
        } catch (SecurityException | SignatureException e) {
            LOG.error("Could not validate signature on AuthnRequest", e);
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        return Response.ok(authnRequest.toString()).build();
    }
}
