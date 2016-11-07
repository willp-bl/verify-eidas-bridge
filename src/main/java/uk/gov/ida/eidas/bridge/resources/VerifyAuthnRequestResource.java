package uk.gov.ida.eidas.bridge.resources;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.eidas.bridge.helpers.AuthnRequestHandler;
import uk.gov.ida.saml.core.api.CoreTransformersFactory;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.hub.transformers.inbound.decorators.AuthnRequestSizeValidator;
import uk.gov.ida.saml.hub.validators.StringSizeValidator;
import uk.gov.ida.saml.metadata.MetadataConfiguration;
import uk.gov.ida.saml.security.MetadataBackedSignatureValidator;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.function.Function;

@Path("/SAML2/SSO/POST")
@Produces(MediaType.APPLICATION_JSON)
public class VerifyAuthnRequestResource {

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
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        return Response.ok(authnRequest.toString()).build();
    }
}
