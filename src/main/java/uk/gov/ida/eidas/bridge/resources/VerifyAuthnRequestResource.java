package uk.gov.ida.eidas.bridge.resources;

import io.dropwizard.auth.Auth;
import io.dropwizard.views.View;
import org.dhatim.dropwizard.jwt.cookie.authentication.DefaultJwtCookiePrincipal;
import org.hibernate.validator.constraints.NotBlank;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.eidas.bridge.SamlRequest;
import uk.gov.ida.eidas.bridge.domain.CountryRepository;
import uk.gov.ida.eidas.bridge.helpers.RandomIdGenerator;
import uk.gov.ida.eidas.bridge.helpers.requestFromVerify.AuthnRequestHandler;
import uk.gov.ida.eidas.bridge.helpers.requestToEidas.AuthnRequestFormGenerator;
import uk.gov.ida.eidas.bridge.views.AuthnRequestFormView;
import uk.gov.ida.eidas.bridge.views.ChooseACountryView;
import uk.gov.ida.saml.core.domain.AuthnContext;
import uk.gov.ida.saml.core.transformers.AuthnContextFactory;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

@Path("/")
public class VerifyAuthnRequestResource {
    private static final String SINGLE_SIGN_ON_PATH = "/SAML2/SSO/POST";

    private final AuthnRequestHandler authnRequestHandler;
    private final AuthnRequestFormGenerator eidasAuthnRequestFormGenerator;
    private CountryRepository countryRepository;

    public VerifyAuthnRequestResource(AuthnRequestHandler authnRequestHandler, AuthnRequestFormGenerator eidasAuthnRequestFormGenerator, CountryRepository countryRepository) {
        this.authnRequestHandler = authnRequestHandler;
        this.eidasAuthnRequestFormGenerator = eidasAuthnRequestFormGenerator;
        this.countryRepository = countryRepository;
    }

    @POST
    @Path(SINGLE_SIGN_ON_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response receiveAuthnRequest(
            @Context ContainerRequestContext requestContext,
            @NotBlank @FormParam("SAMLRequest") String authnRequestStr,
            @NotBlank @FormParam("RelayState") String relayState) throws SignatureException, SecurityException {
        AuthnRequest authnRequest = authnRequestHandler.handleAuthnRequest(authnRequestStr);

        String authnRequestId = authnRequest.getID();

        RequestedAuthnContext requestedAuthnContext = authnRequest.getRequestedAuthnContext();

        AuthnContextFactory authnContextFactory = new AuthnContextFactory();
        AuthnContext lowestAuthnContext = requestedAuthnContext.getAuthnContextClassRefs()
            .stream()
            .map(x -> authnContextFactory.authnContextForLevelOfAssurance(x.getAuthnContextClassRef()))
            .min(AuthnContext::compareTo)
            .orElseThrow(() -> new SecurityException("Expected to find at least 1 Level of Assurance in requested authn context"));

        DefaultJwtCookiePrincipal principal = new DefaultJwtCookiePrincipal("bridge-session");
        principal.getClaims().put("inboundRelayState", relayState);
        principal.getClaims().put("inboundID", authnRequestId);
        principal.getClaims().put("lowestLOA", lowestAuthnContext);

        principal.addInContext(requestContext);

        return Response.seeOther(UriBuilder.fromUri("/choose-a-country").build()).build();
    }

    @GET
    @Path("/choose-a-country")
    @Produces(MediaType.TEXT_HTML)
    public View getCountryPicker(@Auth DefaultJwtCookiePrincipal principal) {
        return new ChooseACountryView(countryRepository.getEnabledCountries());
    }

    @POST
    @Path("/choose-a-country")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response postCountryPicker(
        @Auth DefaultJwtCookiePrincipal principal,
        @NotBlank @FormParam("country") String country) {
        return Response.seeOther(UriBuilder.fromUri("/redirect-to-eidas/" + country).build()).build();
    }

    @GET
    @Path("/redirect-to-eidas/{country}")
    @Produces(MediaType.TEXT_HTML)
    public View getRedirectForm(@Auth DefaultJwtCookiePrincipal principal, @PathParam("country") String country) throws MarshallingException, SignatureException, SecurityException {
        String outboundID = RandomIdGenerator.generateRandomId();
        principal.getClaims().put("outboundID",  outboundID);
        String destinationEntityId = countryRepository.fetchEntityId(country);
        principal.getClaims().put("country",  destinationEntityId);

        String lowestAuthnContext = principal.getClaims().get("lowestLOA", String.class);
        SamlRequest samlRequest = eidasAuthnRequestFormGenerator.generateAuthnRequestForm(outboundID, destinationEntityId, AuthnContext.valueOf(lowestAuthnContext));
        return new AuthnRequestFormView(samlRequest.getAuthnRequest(), samlRequest.getSingleSignOnLocation());
    }
}
