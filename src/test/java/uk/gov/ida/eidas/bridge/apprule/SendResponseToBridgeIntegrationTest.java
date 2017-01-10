package uk.gov.ida.eidas.bridge.apprule;

import com.google.common.collect.ImmutableMap;
import com.google.common.hash.Hashing;
import io.dropwizard.client.JerseyClientBuilder;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.glassfish.jersey.client.ClientProperties;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseUnmarshaller;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import uk.gov.ida.eidas.bridge.helpers.responseFromEidas.EidasIdentityAssertionUnmarshaller;
import uk.gov.ida.eidas.bridge.resources.EidasResponseResource;
import uk.gov.ida.eidas.bridge.rules.BridgeAppRule;
import uk.gov.ida.eidas.bridge.rules.MetadataRule;
import uk.gov.ida.eidas.bridge.testhelpers.NodeMetadataFactory;
import uk.gov.ida.saml.core.extensions.StringBasedMdsAttributeValue;
import uk.gov.ida.saml.core.extensions.impl.StringBasedMdsAttributeValueBuilder;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.core.test.builders.AssertionBuilder;
import uk.gov.ida.saml.core.test.builders.AttributeStatementBuilder;
import uk.gov.ida.saml.core.test.builders.IssuerBuilder;
import uk.gov.ida.saml.core.test.builders.ResponseBuilder;
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
    private static final String SOME_RESPONSE_ID = "some-response-id";
    private static Client client;

    @ClassRule
    public static final MetadataRule verifyMetadata = MetadataRule.verifyMetadata(uri -> new MetadataFactory().defaultMetadata());

    @ClassRule
    public static final MetadataRule eidasMetadata = MetadataRule.eidasMetadata(NodeMetadataFactory::createNodeIdpMetadata);

    @ClassRule
    public static final BridgeAppRule RULE = BridgeAppRule.createBridgeAppRule(verifyMetadata::url, ImmutableMap.of("FR", eidasMetadata::url));

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
        jwtBuilder.claim("country", eidasMetadata.url());

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
        jwtBuilder.claim("country", eidasMetadata.url());

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
    public void shouldRejectsResponseWhenCountryInCookieIsNotDefined() throws Exception {
        ResponseBuilder responseBuilder = getResponseBuilder();
        String responseString = buildString(responseBuilder);

        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.put("SAMLResponse", singletonList(responseString));

        JwtBuilder jwtBuilder = Jwts.builder().signWith(HS256, getSecretSessionKey()).setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
        jwtBuilder.claim("outboundID", SOME_RESPONSE_ID);
        jwtBuilder.claim("country", "OTHER_COUNTRY");

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
    public void shouldRejectsResponseWhenIssuerDoesntMatchCountryClaim() throws Exception {
        ResponseBuilder responseBuilder = getResponseBuilder();
        String responseString = buildString(responseBuilder.withIssuer(IssuerBuilder.anIssuer().withIssuerId("fooBar").build()));

        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.put("SAMLResponse", singletonList(responseString));

        JwtBuilder jwtBuilder = Jwts.builder().signWith(HS256, getSecretSessionKey()).setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
        jwtBuilder.claim("outboundID", SOME_RESPONSE_ID);
        jwtBuilder.claim("country", eidasMetadata.url());

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
        jwtBuilder.claim("country", eidasMetadata.url());

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
        attributeStatementBuilder.addAttribute(createAttribute(EidasIdentityAssertionUnmarshaller.PERSON_IDENTIFIER_URI, "personNumber1337"));

        AssertionBuilder assertionBuilder = anAssertion().addAttributeStatement(attributeStatementBuilder.build());
        Issuer issuer = IssuerBuilder.anIssuer().withIssuerId(eidasMetadata.url()).build();
        Issuer issuerAssertion = IssuerBuilder.anIssuer().withIssuerId(eidasMetadata.url()).build();
        return aResponse().withInResponseTo(SOME_RESPONSE_ID)
                .withIssuer(issuer)
                .addEncryptedAssertion(assertionBuilder.withIssuer(issuerAssertion).buildWithEncrypterCredential(createEncrypter()));
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
        return Optional.of(RULE.getSecretSeed())
            .map(seed -> Hashing.sha256().newHasher().putString(seed, UTF_8).hash().asBytes())
            .map(k -> (Key) new SecretKeySpec(k, HS256.getJcaName())).get();
    }

    /**
     * Build an encrypter to mimic the encryption done by eIDAS.
     * @return An encrypter using the aes256-gcm cipher (which is the cipher used by the eIDAS node)
     */
    private Encrypter createEncrypter() {
        TestCredentialFactory testCredentialFactory = new TestCredentialFactory(TestCertificateStrings.TEST_PUBLIC_CERT, null);
        DataEncryptionParameters encParams = new DataEncryptionParameters();
        //TODO support JCE on jenkins
        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM);

        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(testCredentialFactory.getEncryptingCredential());
        kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

        Encrypter encrypter = new Encrypter(encParams, kekParams);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);

        return encrypter;

    }

}
