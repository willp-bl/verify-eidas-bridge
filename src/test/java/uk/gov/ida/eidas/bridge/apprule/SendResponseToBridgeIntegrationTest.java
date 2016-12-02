package uk.gov.ida.eidas.bridge.apprule;

import com.google.common.hash.Hashing;
import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.junit.DropwizardAppRule;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.glassfish.jersey.client.ClientProperties;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Test;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseUnmarshaller;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;
import uk.gov.ida.eidas.bridge.BridgeApplication;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.factories.VerifyEidasBridgeFactory;
import uk.gov.ida.eidas.bridge.helpers.EidasIdentityAssertionUnmarshaller;
import uk.gov.ida.eidas.bridge.resources.EidasResponseResource;
import uk.gov.ida.eidas.bridge.rules.MetadataRule;
import uk.gov.ida.eidas.bridge.testhelpers.TestSigningKeyStoreProvider;
import uk.gov.ida.saml.core.extensions.StringBasedMdsAttributeValue;
import uk.gov.ida.saml.core.extensions.impl.StringBasedMdsAttributeValueBuilder;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.core.test.builders.AssertionBuilder;
import uk.gov.ida.saml.core.test.builders.AttributeStatementBuilder;
import uk.gov.ida.saml.core.test.builders.ResponseBuilder;
import uk.gov.ida.saml.core.test.builders.SimpleMdsValueBuilder;
import uk.gov.ida.saml.metadata.test.factories.metadata.EntitiesDescriptorFactory;
import uk.gov.ida.saml.metadata.test.factories.metadata.EntityDescriptorFactory;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;
import uk.gov.ida.shared.utils.string.StringEncoding;
import uk.gov.ida.shared.utils.xml.XmlUtils;

import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.Response;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;

import static com.google.common.collect.ImmutableList.of;
import static io.jsonwebtoken.SignatureAlgorithm.HS256;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singletonList;
import static org.apache.commons.codec.binary.Base64.encodeBase64;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static uk.gov.ida.eidas.bridge.testhelpers.ResponseStringBuilder.aResponse;
import static uk.gov.ida.eidas.bridge.testhelpers.ResponseStringBuilder.buildString;
import static uk.gov.ida.saml.core.test.builders.AssertionBuilder.anAssertion;
import static uk.gov.ida.saml.core.test.builders.AttributeStatementBuilder.anAttributeStatement;

public class SendResponseToBridgeIntegrationTest {
    public static final String SOME_RESPONSE_ID = "some-response-id";
    private static Client client;

    public static final String SECRET_SEED = "foobar";

    private static final String eidasEntityId = TestCertificateStrings.TEST_ENTITY_ID;

    private static final EntityDescriptor eidasEntityDescriptor = new EntityDescriptorFactory().idpEntityDescriptor(eidasEntityId);
    @ClassRule
    public static final MetadataRule verifyMetadata = MetadataRule.verifyMetadata(new MetadataFactory().defaultMetadata());

    @ClassRule
    public static final MetadataRule eidasMetadata = MetadataRule.eidasMetadata(
        new MetadataFactory().metadata(new EntitiesDescriptorFactory().entitiesDescriptor(singletonList(eidasEntityDescriptor))));

    private static final String KEYSTORE_PASSWORD = "fooBar";
    private static final String encodedSigningKeyStore = TestSigningKeyStoreProvider.getBase64EncodedSigningKeyStore(VerifyEidasBridgeFactory.SIGNING_KEY_ALIAS, KEYSTORE_PASSWORD);
    private static final String encodedEncryptingKeyStore = TestSigningKeyStoreProvider.getBase64EncodedSigningKeyStore(VerifyEidasBridgeFactory.ENCRYPTING_KEY_ALIAS, KEYSTORE_PASSWORD);
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String HOSTNAME = "hostname";

    @ClassRule
    public static final DropwizardAppRule<BridgeConfiguration> RULE = new DropwizardAppRule<>(BridgeApplication.class,
        "eidasbridge-test.yml",
        ConfigOverride.config("verifyMetadata.trustStorePath", "test_metadata_truststore.ts"),
        ConfigOverride.config("verifyMetadata.uri", verifyMetadata::url),
        ConfigOverride.config("eidasMetadata.trustStorePath", "test_metadata_truststore.ts"),
        ConfigOverride.config("eidasMetadata.uri", eidasMetadata::url),
        ConfigOverride.config("eidasNodeEntityId", eidasEntityId),
        ConfigOverride.config("signingKeyStore.base64Value", encodedSigningKeyStore),
        ConfigOverride.config("signingKeyStore.password", KEYSTORE_PASSWORD),
        ConfigOverride.config("signingKeyStore.type", KEYSTORE_TYPE),
        ConfigOverride.config("encryptingKeyStore.base64Value", encodedEncryptingKeyStore),
        ConfigOverride.config("encryptingKeyStore.password", KEYSTORE_PASSWORD),
        ConfigOverride.config("encryptingKeyStore.type", KEYSTORE_TYPE),
        ConfigOverride.config("hostname", HOSTNAME),
        ConfigOverride.config("sessionCookie.secretSeed", SECRET_SEED)//,
        //ConfigOverride.config("bridgeEntityId", "")
    );

    @BeforeClass
    public static void before() {
        client = new JerseyClientBuilder(RULE.getEnvironment()).build("bridge test client");
    }

    @Test
    public void shouldAcceptsResponseWithValidSignature() throws Exception {
        String responseString = buildString(getResponseBuilder());

        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.put("SAMLResponse", singletonList(responseString));

        JwtBuilder jwtBuilder = Jwts.builder().signWith(HS256, getSecretSessionKey()).setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
        jwtBuilder.claim("outboundID", SOME_RESPONSE_ID);

        Response result = client
            .property(ClientProperties.FOLLOW_REDIRECTS, false)
            .target(String.format("http://localhost:%d%s", RULE.getLocalPort(), EidasResponseResource.ASSERTION_CONSUMER_PATH))
            .request()
            .cookie("sessionToken", jwtBuilder.compact())
            .buildPost(Entity.form(form))
            .invoke();

        assertEquals(Response.Status.OK.getStatusCode(), result.getStatus());
    }

    @Test
    public void shouldRejectsResponseWithInvalidSignature() throws Exception {
        ResponseBuilder responseBuilder = getResponseBuilder();
        Credential signingCredential = new TestCredentialFactory(TestCertificateStrings.UNCHAINED_PUBLIC_CERT, TestCertificateStrings.UNCHAINED_PRIVATE_KEY).getSigningCredential();
        responseBuilder.withSigningCredential(signingCredential);
        String responseString = buildString(responseBuilder);

        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.put("SAMLResponse", singletonList(responseString));

        JwtBuilder jwtBuilder = Jwts.builder().signWith(HS256, getSecretSessionKey()).setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
        jwtBuilder.claim("outboundID", SOME_RESPONSE_ID);

        Response result = client
            .property(ClientProperties.FOLLOW_REDIRECTS, false)
            .target(String.format("http://localhost:%d%s", RULE.getLocalPort(), EidasResponseResource.ASSERTION_CONSUMER_PATH))
            .request()
            .cookie("sessionToken", jwtBuilder.compact())
            .buildPost(Entity.form(form))
            .invoke();

        assertEquals(400, result.getStatus());
    }

    @Test
    public void testRendersResponseInForm() throws Exception {
        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.put("SAMLResponse", singletonList(buildString(getResponseBuilder())));

        JwtBuilder jwtBuilder = Jwts.builder().signWith(HS256, getSecretSessionKey()).setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
        jwtBuilder.claim("outboundID", SOME_RESPONSE_ID);

        Response response = client
            .property(ClientProperties.FOLLOW_REDIRECTS, false)
            .target(String.format("http://localhost:%d%s", RULE.getLocalPort(), EidasResponseResource.ASSERTION_CONSUMER_PATH))
            .request()
            .cookie("sessionToken", jwtBuilder.compact())
            .buildPost(Entity.form(form))
            .invoke();

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

        String responseString = response.readEntity(String.class);

        Document doc = Jsoup.parseBodyFragment(responseString);
        Element samlResponse = doc.getElementsByAttributeValue("name", "SAMLResponse").first();

        assertNotNull("Expected to find a SAMLResponse in the form", samlResponse);
        String samlResponseValue = samlResponse.attr("value");
        org.w3c.dom.Element samlResponseXml = XmlUtils.convertToElement(StringEncoding.fromBase64Encoded(samlResponseValue));
        org.opensaml.saml.saml2.core.Response samlResponseSaml = (org.opensaml.saml.saml2.core.Response) new ResponseUnmarshaller().unmarshall(samlResponseXml);
        assertNotNull(samlResponseSaml);
    }

    private ResponseBuilder getResponseBuilder() {
        AttributeStatementBuilder attributeStatementBuilder = anAttributeStatement();

        String eidasAddress = new String(encodeBase64("<some-xml>This is my address</some-xml>".getBytes()));
        attributeStatementBuilder.addAttribute(createAttribute(EidasIdentityAssertionUnmarshaller.FIRST_NAME_URI, "BANANA"));
        attributeStatementBuilder.addAttribute(createAttribute(EidasIdentityAssertionUnmarshaller.FAMILY_NAME_URI, "NANA"));
        attributeStatementBuilder.addAttribute(createAttribute(EidasIdentityAssertionUnmarshaller.CURRENT_ADDRESS_URI, eidasAddress));
        attributeStatementBuilder.addAttribute(createAttribute(EidasIdentityAssertionUnmarshaller.GENDER_URI, "Female"));
        attributeStatementBuilder.addAttribute(createAttribute(EidasIdentityAssertionUnmarshaller.DATE_OF_BIRTH_URI, "1960-01-01"));

        AssertionBuilder assertionBuilder = anAssertion().addAttributeStatement(attributeStatementBuilder.build());
        return aResponse().withInResponseTo(SOME_RESPONSE_ID)
            .addEncryptedAssertion(assertionBuilder.build());
    }

    private Attribute createAttribute(String key, String value) {
        Attribute attribute = new AttributeBuilder().buildObject();
        attribute.setName(key);
        StringBasedMdsAttributeValue attributeValue = new StringBasedMdsAttributeValueBuilder().buildObject();
        attributeValue.setValue(value);
        attribute.getAttributeValues().add(attributeValue);
        return attribute;
    }

    private Key getSecretSessionKey() {
        return Optional.of(SECRET_SEED)
            .map(seed -> Hashing.sha256().newHasher().putString(seed, UTF_8).hash().asBytes())
            .map(k -> (Key) new SecretKeySpec(k, HS256.getJcaName())).get();
    }

}
