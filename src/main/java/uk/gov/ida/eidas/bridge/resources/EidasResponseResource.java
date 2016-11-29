package uk.gov.ida.eidas.bridge.resources;

import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.eidas.bridge.helpers.ResponseHandler;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
@Produces(MediaType.APPLICATION_XML)
public class EidasResponseResource {
    private static final Logger LOG = LoggerFactory.getLogger(EidasResponseResource.class);
    public final static String ASSERTION_CONSUMER_PATH = "/SAML2/SSO/Response/POST";

    private final ResponseHandler responseHandler;

    public EidasResponseResource(ResponseHandler responseHandler) {
        this.responseHandler = responseHandler;
    }

    @POST
    @Path(ASSERTION_CONSUMER_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response receiveResponse(@FormParam("SAMLRequest") String responseStr) {
        try {
            responseHandler.handleResponse(responseStr);
        } catch (SignatureException | SecurityException e) {
            LOG.error("Could not validate signature on Response", e);
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        return Response.ok().build();
    }

}
