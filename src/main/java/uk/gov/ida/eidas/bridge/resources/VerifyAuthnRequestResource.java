package uk.gov.ida.eidas.bridge.resources;

import io.dropwizard.auth.Auth;
import io.dropwizard.views.View;
import org.dhatim.dropwizard.jwt.cookie.authentication.DefaultJwtCookiePrincipal;
import org.hibernate.validator.constraints.NotBlank;
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
import javax.ws.rs.Produces;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.util.UUID;

@Path("/")
public class VerifyAuthnRequestResource {

    private static final Logger LOG = LoggerFactory.getLogger(VerifyAuthnRequestResource.class);
    public static final String SINGLE_SIGN_ON_PATH = "/SAML2/SSO/POST";

    private final AuthnRequestHandler authnRequestHandler;
    private AuthnRequestFormGenerator eidasAuthnRequestFormGenerator;

    public VerifyAuthnRequestResource(AuthnRequestHandler authnRequestHandler, AuthnRequestFormGenerator eidasAuthnRequestFormGenerator) {
        this.authnRequestHandler = authnRequestHandler;
        this.eidasAuthnRequestFormGenerator = eidasAuthnRequestFormGenerator;
    }

    @POST
    @Path(SINGLE_SIGN_ON_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response receiveAuthnRequest(
            @Context ContainerRequestContext requestContext,
            @NotBlank @FormParam("SAMLRequest") String authnRequestStr,
            @NotBlank @FormParam("RelayState") String relayState) {
        AuthnRequest authnRequest;
        try {
            authnRequest = authnRequestHandler.handleAuthnRequest(authnRequestStr);
        } catch (SecurityException | SignatureException e) {
            LOG.error("Could not validate signature on AuthnRequest", e);
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        String authnRequestId = authnRequest.getID();

        DefaultJwtCookiePrincipal principal = new DefaultJwtCookiePrincipal("bridge-session");
        principal.getClaims().put("inboundRelayState", relayState);
        principal.getClaims().put("inboundID", authnRequestId);
        principal.addInContext(requestContext);

        return Response.seeOther(UriBuilder.fromUri("/redirect-to-eidas").build()).build();
    }

    @GET
    @Path("/redirect-to-eidas")
    @Produces(MediaType.TEXT_HTML)
    public View getRedirectForm(@Auth DefaultJwtCookiePrincipal principal) throws MarshallingException, SignatureException, SecurityException {
        String outboundID = generateRandomId();
        principal.getClaims().put("outboundID",  outboundID);
        SamlRequest samlRequest = eidasAuthnRequestFormGenerator.generateAuthnRequestForm(outboundID);
        return new AuthnRequestFormView(samlRequest.getAuthnRequest(), samlRequest.getSingleSignOnLocation());
    }

    private String generateRandomId(){
        // The ID needs to conform to the NCName specification. From https://www.w3.org/TR/1999/REC-xml-names-19990114/#NT-NCName
        //
        //       NCName    ::=    (Letter | '_') (NCNameChar)*
        //   NCNameChar    ::=    Letter | Digit | '.' | '-' | '_' | CombiningChar | Extender

        return "_" + UUID.randomUUID().toString();
    }

}
