package uk.gov.ida.eidas.bridge.resources;

import io.dropwizard.auth.Auth;
import io.dropwizard.views.View;
import org.dhatim.dropwizard.jwt.cookie.authentication.DefaultJwtCookiePrincipal;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.eidas.bridge.domain.EidasSamlResponse;
import uk.gov.ida.eidas.bridge.helpers.responseFromEidas.ResponseHandler;
import uk.gov.ida.eidas.bridge.helpers.responseToVerify.AssertionConsumerServiceLocator;
import uk.gov.ida.eidas.bridge.helpers.responseToVerify.VerifyResponseGenerator;
import uk.gov.ida.eidas.bridge.views.ResponseFormView;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

@Path("/")
public class EidasResponseResource {
    private static final Logger LOG = LoggerFactory.getLogger(EidasResponseResource.class);

    public final static String ASSERTION_CONSUMER_PATH = "/SAML2/SSO/Response/POST";

    private final String verifyEntityId;
    private final XmlObjectToBase64EncodedStringTransformer xmlObjectToBase64EncodedStringTransformer;
    private final ResponseHandler responseHandler;
    private final VerifyResponseGenerator responseGenerator;
    private final AssertionConsumerServiceLocator assertionConsumerServiceLocator;

    public EidasResponseResource(
        String verifyEntityId, XmlObjectToBase64EncodedStringTransformer xmlObjectToBase64EncodedStringTransformer,
        ResponseHandler responseHandler,
        VerifyResponseGenerator responseGenerator,
        AssertionConsumerServiceLocator assertionConsumerServiceLocator) {
        this.verifyEntityId = verifyEntityId;
        this.xmlObjectToBase64EncodedStringTransformer = xmlObjectToBase64EncodedStringTransformer;
        this.responseHandler = responseHandler;
        this.responseGenerator = responseGenerator;
        this.assertionConsumerServiceLocator = assertionConsumerServiceLocator;
    }

    @POST
    @Path(ASSERTION_CONSUMER_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public View handleEidasResponseAndTranslateIntoVerifyResponse (
        @Context HttpServletRequest req,
        @FormParam("SAMLResponse") @NotNull String responseStr,
        @Auth DefaultJwtCookiePrincipal principal) throws MarshallingException, SecurityException, SignatureException {
        String outboundID = principal.getClaims().get("outboundID", String.class);
        String entityId = principal.getClaims().get("country", String.class);

        EidasSamlResponse eidasSamlResponse = responseHandler.handleResponse(responseStr, outboundID, entityId);
        String inboundID = principal.getClaims().get("inboundID", String.class);
        String assertionConsumerServiceLocation = assertionConsumerServiceLocator.getAssertionConsumerServiceLocation(verifyEntityId);
        org.opensaml.saml.saml2.core.Response response = responseGenerator.generateResponse(assertionConsumerServiceLocation, inboundID, req.getRemoteAddr(), eidasSamlResponse);

        return new ResponseFormView(xmlObjectToBase64EncodedStringTransformer.apply(response), assertionConsumerServiceLocation, principal.getClaims().get("inboundRelayState", String.class));
    }
}
