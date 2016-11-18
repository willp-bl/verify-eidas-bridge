package uk.gov.ida.eidas.bridge.apprule;

import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit.DropwizardAppRule;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.glassfish.jersey.client.ClientProperties;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestUnmarshaller;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.xml.sax.SAXException;
import uk.gov.ida.eidas.bridge.BridgeApplication;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.rules.MetadataRule;
import uk.gov.ida.eidas.bridge.testhelpers.TestSignatureValidator;
import uk.gov.ida.eidas.bridge.testhelpers.TestSigningKeyStoreProvider;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;
import uk.gov.ida.shared.utils.string.StringEncoding;
import uk.gov.ida.shared.utils.xml.XmlUtils;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.Response;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static uk.gov.ida.eidas.bridge.testhelpers.AuthnRequestBuilder.anAuthnRequest;


public class SendAuthnRequestToBridgeIntegrationTest {
    public static final String KEYSTORE_PASSWORD = "fooBar";

    private static Client client;

    @ClassRule
    public static final MetadataRule metadataMock = new MetadataRule(new MetadataFactory().defaultMetadata(), wireMockConfig().dynamicPort());

    private static final String encodedSigningKeyStore = TestSigningKeyStoreProvider.getBase64EncodedSigningKeyStore(KEYSTORE_PASSWORD);

    public static final String PKCS_12 = "PKCS12";

    private static final String HOSTNAME = "hostname";

    @ClassRule
    public static final DropwizardAppRule<BridgeConfiguration> RULE = new DropwizardAppRule<>(BridgeApplication.class,
        ResourceHelpers.resourceFilePath("eidasbridge.yml"),
        ConfigOverride.config("verifyMetadata.trustStorePath", ResourceHelpers.resourceFilePath("test_metadata_truststore.ts")),
        ConfigOverride.config("verifyMetadata.uri", metadataMock::verifyUrl),
        ConfigOverride.config("eidasMetadata.trustStorePath", ResourceHelpers.resourceFilePath("test_metadata_truststore.ts")),
        ConfigOverride.config("eidasMetadata.uri", metadataMock::eidasUrl),
        ConfigOverride.config("signingKeyStore.base64Value", encodedSigningKeyStore),
        ConfigOverride.config("signingKeyStore.password", KEYSTORE_PASSWORD),
        ConfigOverride.config("signingKeyStore.type", PKCS_12),
        ConfigOverride.config("hostname", HOSTNAME)
    );

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

        Response result = client
            .property(ClientProperties.FOLLOW_REDIRECTS, false)
            .target(String.format("http://localhost:%d/SAML2/SSO/POST", RULE.getLocalPort()))
            .request()
            .buildPost(Entity.form(form))
            .invoke();

        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), result.getStatus());
    }


    @Test
    public void testRendersSAMLForm() throws MarshallingException, SignatureException, Base64DecodingException, ParserConfigurationException, UnmarshallingException, SAXException, IOException, SecurityException {
        Response result = client
            .target(String.format("http://localhost:%d/redirect-to-eidas/anId", RULE.getLocalPort()))
            .request()
            .get();
        String responseString = result.readEntity(String.class);

        Document doc = Jsoup.parseBodyFragment(responseString);
        Element samlRequest = doc.getElementsByAttributeValue("name", "SAMLRequest").first();

        Assert.assertNotNull(samlRequest);
        String samlRequestValue = samlRequest.val();
        Assert.assertNotNull(samlRequestValue);

        AuthnRequest authnRequest = (AuthnRequest) new AuthnRequestUnmarshaller().unmarshall(XmlUtils.convertToElement(StringEncoding.fromBase64Encoded(samlRequestValue)));
        assertThat(TestSignatureValidator.getSignatureValidator().validate(authnRequest, null, SPSSODescriptor.DEFAULT_ELEMENT_NAME)).isTrue();
        String entityId = authnRequest.getIssuer().getValue();
        assertEquals(HOSTNAME + "/metadata", entityId);
    }

    @Test
    public void testRejectsAuthnRequestWithInvalidSignature() throws MarshallingException, SignatureException {
        String authnRequest = anAuthnRequest()
            .withSigningCredentials(TestCertificateStrings.UNCHAINED_PUBLIC_CERT, TestCertificateStrings.UNCHAINED_PRIVATE_KEY)
            .buildString();

        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.put("SAMLRequest", singletonList(authnRequest));

        Response result = client
            .target(String.format("http://localhost:%d/SAML2/SSO/POST", RULE.getLocalPort()))
            .request()
            .buildPost(Entity.form(form))
            .invoke();

        assertEquals(400, result.getStatus());
    }

}
