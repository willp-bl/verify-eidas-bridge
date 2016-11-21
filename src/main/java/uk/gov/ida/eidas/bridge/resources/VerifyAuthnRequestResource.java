package uk.gov.ida.eidas.bridge.resources;

import io.dropwizard.views.View;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.eidas.bridge.SamlRequest;
import uk.gov.ida.eidas.bridge.helpers.AuthnRequestFormGenerator;
import uk.gov.ida.eidas.bridge.helpers.AuthnRequestHandler;
import uk.gov.ida.eidas.bridge.views.AuthnRequestFormView;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class VerifyAuthnRequestResource {

    private static final Logger LOG = LoggerFactory.getLogger(VerifyAuthnRequestResource.class);

    private final AuthnRequestHandler authnRequestHandler;
    private AuthnRequestFormGenerator eidasAuthnRequestFormGenerator;

    public VerifyAuthnRequestResource(AuthnRequestHandler authnRequestHandler, AuthnRequestFormGenerator eidasAuthnRequestFormGenerator) {
        this.authnRequestHandler = authnRequestHandler;
        this.eidasAuthnRequestFormGenerator = eidasAuthnRequestFormGenerator;
    }

    @POST
    @Path("/SAML2/SSO/POST")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response receiveAuthnRequest(@FormParam("SAMLRequest") String authnRequestStr) {
        AuthnRequest authnRequest;
        try {
            authnRequest = authnRequestHandler.handleAuthnRequest(authnRequestStr);
        } catch (SecurityException | SignatureException e) {
            LOG.error("Could not validate signature on AuthnRequest", e);
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        String authnRequestId = authnRequest.getID();
        return Response.seeOther(UriBuilder.fromUri("/redirect-to-eidas/" + authnRequestId).build()).build();
    }

    @GET
    @Path("/redirect-to-eidas/{authnRequestId: .+}")
    @Produces(MediaType.TEXT_HTML)
    public View getRedirectForm(@PathParam("authnRequestId") String authnRequestId) throws MarshallingException, SignatureException {
        SamlRequest samlRequest = eidasAuthnRequestFormGenerator.generateAuthnRequestForm(authnRequestId);
        return new AuthnRequestFormView(samlRequest.getAuthnRequest(), samlRequest.getSingleSignOnLocation());
    }

}
