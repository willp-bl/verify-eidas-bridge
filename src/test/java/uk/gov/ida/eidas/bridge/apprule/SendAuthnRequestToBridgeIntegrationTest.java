package uk.gov.ida.eidas.bridge.apprule;

import com.google.common.hash.Hashing;
import io.dropwizard.client.JerseyClientBuilder;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.http.HttpStatus;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.glassfish.jersey.client.ClientProperties;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestUnmarshaller;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.xml.sax.SAXException;
import uk.gov.ida.eidas.bridge.rules.BridgeAppRule;
import uk.gov.ida.eidas.bridge.rules.MetadataRule;
import uk.gov.ida.eidas.bridge.testhelpers.TestSignatureValidator;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.metadata.test.factories.metadata.EntitiesDescriptorFactory;
import uk.gov.ida.saml.metadata.test.factories.metadata.EntityDescriptorFactory;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;
import uk.gov.ida.shared.utils.string.StringEncoding;
import uk.gov.ida.shared.utils.xml.XmlUtils;

import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static io.jsonwebtoken.SignatureAlgorithm.HS256;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static uk.gov.ida.eidas.bridge.testhelpers.AuthnRequestBuilder.anAuthnRequest;


public class SendAuthnRequestToBridgeIntegrationTest {
    private static final String KEYSTORE_PASSWORD = "fooBar";

    private static Client client;

    private static final String SECRET_SEED = "foobar";
    private static final String eidasEntityId = "foobar";
    private static final EntityDescriptor eidasEntityDescriptor = new EntityDescriptorFactory().idpEntityDescriptor(eidasEntityId);

    @ClassRule
    public static final MetadataRule verifyMetadata = MetadataRule.verifyMetadata(new MetadataFactory().defaultMetadata());

    @ClassRule
    public static final MetadataRule eidasMetadata = MetadataRule.eidasMetadata(
        new MetadataFactory().metadata(new EntitiesDescriptorFactory().entitiesDescriptor(singletonList(eidasEntityDescriptor))));

    @ClassRule
    public static final BridgeAppRule RULE = new BridgeAppRule(verifyMetadata::url, eidasMetadata::url, eidasEntityId);

    @BeforeClass
    public static void before() {
        client = new JerseyClientBuilder(RULE.getEnvironment()).build("bridge test client");
    }


    @Test
    public void testAcceptsAuthnRequestWithValidSignatureAndRedirects() throws MarshallingException, SignatureException {
        String authnRequest = anAuthnRequest()
            .withSigningCredentials(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT, TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY)
            .buildString();

        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.put("SAMLRequest", singletonList(authnRequest));
        form.put("RelayState", singletonList("my-relay-state"));

        Response result = client
            .property(ClientProperties.FOLLOW_REDIRECTS, false)
            .target(String.format("http://localhost:%d/SAML2/SSO/POST", RULE.getLocalPort()))
            .request()
            .buildPost(Entity.form(form))
            .invoke();

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), result.getStatus());
    }

    @Test
    public void testAcceptsAuthnAndCreatesSessionCookie() throws MarshallingException, SignatureException {
        String id = "MY TEST ID";
        String authnRequest = anAuthnRequest().withID(id)
                .withSigningCredentials(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT, TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY)
                .buildString();

        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.put("SAMLRequest", singletonList(authnRequest));
        String relayState = UUID.randomUUID().toString();
        form.put("RelayState", singletonList(relayState));

        Response result = client
                .property(ClientProperties.FOLLOW_REDIRECTS, false)
                .target(String.format("http://localhost:%d/SAML2/SSO/POST", RULE.getLocalPort()))
                .request()
                .buildPost(Entity.form(form))
                .invoke();

        Claims claims = getSessionTokenClaims(result);

        assertThat(claims.get("inboundRelayState", String.class)).isEqualTo(relayState);
        assertThat(claims.get("inboundID", String.class)).isEqualTo(id);
    }

    private Claims getSessionTokenClaims(Response result) {
        NewCookie sessionToken = result.getCookies().get("sessionToken");

        Key key = getSecretSessionKey();
        return Jwts.parser().setSigningKey(key).parseClaimsJws(sessionToken.getValue()).getBody();
    }

    private Key getSecretSessionKey() {
        return Optional.of(RULE.getSecretSeed())
                    .map(seed -> Hashing.sha256().newHasher().putString(seed, UTF_8).hash().asBytes())
                    .map(k -> (Key) new SecretKeySpec(k, HS256.getJcaName())).get();
    }

    @Test
    public void testShouldReturnUnauthorizedIfCookieMissing() throws MarshallingException, SignatureException, Base64DecodingException, ParserConfigurationException, UnmarshallingException, SAXException, IOException, SecurityException {
        Response response = client
                .target(String.format("http://localhost:%d/redirect-to-eidas", RULE.getLocalPort()))
                .request()
                .get();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    @Test
    public void testShouldReturnUnauthorizedtIfCookieKeyWrong() throws MarshallingException, SignatureException, Base64DecodingException, ParserConfigurationException, UnmarshallingException, SAXException, IOException, SecurityException {
        String sessionToken = Jwts.builder().signWith(HS256, "wrongKey").claim("foo", "bar").compact();
        Response response = client
                .target(String.format("http://localhost:%d/redirect-to-eidas", RULE.getLocalPort()))
                .request()
                .cookie("sessionToken", sessionToken)
                .get();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    @Test
    public void testRendersAuthnRequestInForm() throws MarshallingException, SignatureException, Base64DecodingException, ParserConfigurationException, UnmarshallingException, SAXException, IOException, SecurityException {
        Response response = makeRequestForAuthnRequest();
        String responseString = response.readEntity(String.class);

        Document doc = Jsoup.parseBodyFragment(responseString);
        Element samlRequest = doc.getElementsByAttributeValue("name", "SAMLRequest").first();
        assertNotNull(samlRequest);
        String samlRequestValue = samlRequest.val();
        assertNotNull(samlRequestValue);

        AuthnRequest authnRequest = (AuthnRequest) new AuthnRequestUnmarshaller().unmarshall(XmlUtils.convertToElement(StringEncoding.fromBase64Encoded(samlRequestValue)));

        //ID is recorded in sessionToken
        assertThat(authnRequest.getID()).isEqualTo(getSessionTokenClaims(response).get("outboundID", String.class));

        assertThat(TestSignatureValidator.getSignatureValidator().validate(authnRequest, null, SPSSODescriptor.DEFAULT_ELEMENT_NAME)).isTrue();
        String entityId = authnRequest.getIssuer().getValue();
        assertEquals(RULE.getHostname() + "/metadata", entityId);
    }

    @Test
    public void testRendersSingleSignOnLocationAsFormAction() throws MarshallingException, SignatureException, Base64DecodingException, ParserConfigurationException, UnmarshallingException, SAXException, IOException, SecurityException {
        Response result = makeRequestForAuthnRequest();
        String responseString = result.readEntity(String.class);

        Document doc = Jsoup.parseBodyFragment(responseString);

        Element form = doc.getElementsByTag("form").first();
        assertNotNull(form);

        String expectedSingleSignOnLocation = getExpectedSingleSignOnLocation();
        assertEquals(expectedSingleSignOnLocation, form.attr("action"));
    }

    @Test
    public void testRendersButtonInForm() throws MarshallingException, SignatureException, Base64DecodingException, ParserConfigurationException, UnmarshallingException, SAXException, IOException, SecurityException {
        Response result = makeRequestForAuthnRequest();
        String responseString = result.readEntity(String.class);

        Document doc = Jsoup.parseBodyFragment(responseString);

        assertNotNull(doc.getElementsByAttributeValue("type", "submit").first());
    }

    private Response makeRequestForAuthnRequest() {
        return client
            .target(String.format("http://localhost:%d/redirect-to-eidas", RULE.getLocalPort()))
            .request()
            .cookie("sessionToken", Jwts.builder().signWith(HS256, getSecretSessionKey()).setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS))).compact())
            .get();
    }

    @Test
    public void testRejectsAuthnRequestWithInvalidSignature() throws MarshallingException, SignatureException {
        String authnRequest = anAuthnRequest()
            .withSigningCredentials(TestCertificateStrings.UNCHAINED_PUBLIC_CERT, TestCertificateStrings.UNCHAINED_PRIVATE_KEY)
            .buildString();

        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.put("SAMLRequest", singletonList(authnRequest));
        form.put("RelayState", singletonList(UUID.randomUUID().toString()));

        Response result = client
            .target(String.format("http://localhost:%d/SAML2/SSO/POST", RULE.getLocalPort()))
            .request()
            .buildPost(Entity.form(form))
            .invoke();

        assertEquals(400, result.getStatus());
    }

    private String getExpectedSingleSignOnLocation() {
        IDPSSODescriptor idpssoDescriptor = eidasEntityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
        List<SingleSignOnService> singleSignOnServices = idpssoDescriptor.getSingleSignOnServices();
        return singleSignOnServices.get(0).getLocation();
    }
}
