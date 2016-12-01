package uk.gov.ida.eidas.bridge.apprule;

import com.google.common.hash.Hashing;
import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.junit.DropwizardAppRule;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;
import uk.gov.ida.eidas.bridge.BridgeApplication;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.factories.VerifyEidasBridgeFactory;
import uk.gov.ida.eidas.bridge.resources.EidasResponseResource;
import uk.gov.ida.eidas.bridge.rules.MetadataRule;
import uk.gov.ida.eidas.bridge.testhelpers.TestSigningKeyStoreProvider;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.core.test.builders.ResponseBuilder;
import uk.gov.ida.saml.metadata.test.factories.metadata.EntitiesDescriptorFactory;
import uk.gov.ida.saml.metadata.test.factories.metadata.EntityDescriptorFactory;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;

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
import static uk.gov.ida.eidas.bridge.testhelpers.ResponseStringBuilder.aResponse;
import static uk.gov.ida.eidas.bridge.testhelpers.ResponseStringBuilder.buildString;

public class SendResponseToBridgeIntegrationTest {
    private static Client client;

    public static final String SECRET_SEED = "foobar";

    private static final String eidasEntityId = TestCertificateStrings.TEST_ENTITY_ID;

    private static final EntityDescriptor eidasEntityDescriptor = new EntityDescriptorFactory().idpEntityDescriptor(eidasEntityId);
    @ClassRule
    public static final MetadataRule verifyMetadata = MetadataRule.verifyMetadata(new MetadataFactory().defaultMetadata());

    @ClassRule
    public static final MetadataRule eidasMetadata = MetadataRule.eidasMetadata(
        new MetadataFactory().metadata(new EntitiesDescriptorFactory().entitiesDescriptor(singletonList(eidasEntityDescriptor))));

    public static final String KEYSTORE_PASSWORD = "fooBar";
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
        ConfigOverride.config("sessionCookie.secretSeed", SECRET_SEED)
    );

    @BeforeClass
    public static void before() {
        client = new JerseyClientBuilder(RULE.getEnvironment()).build("bridge test client");
    }

    @Test
    public void shouldAcceptsResponseWithValidSignature() throws Exception {
        String responseId = "some-repsonse-id";
        String responseString = buildString(aResponse().withId(responseId));

        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.put("SAMLResponse", singletonList(responseString));

        JwtBuilder jwtBuilder = Jwts.builder().signWith(HS256, getSecretSessionKey()).setExpiration(Date.from(Instant.now().plus(3600, ChronoUnit.SECONDS)));
        jwtBuilder.claim("outboundID", responseId);

        Response result = client
            .property(ClientProperties.FOLLOW_REDIRECTS, false)
            .target(String.format("http://localhost:%d%s", RULE.getLocalPort(), EidasResponseResource.ASSERTION_CONSUMER_PATH))
            .request()
            .cookie("sessionToken", jwtBuilder.compact())
            .buildPost(Entity.form(form))
            .invoke();

        Assert.assertEquals(200, result.getStatus());
    }

    @Test
    public void shouldRejectsResponseWithInvalidSignature() throws Exception {
        String responseId = "some-repsonse-id";
        ResponseBuilder responseBuilder = aResponse().withId(responseId);
        Credential signingCredential = new TestCredentialFactory(TestCertificateStrings.UNCHAINED_PUBLIC_CERT, TestCertificateStrings.UNCHAINED_PRIVATE_KEY).getSigningCredential();
        responseBuilder.withSigningCredential(signingCredential);
        String responseString = buildString(responseBuilder);

        MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
        form.put("SAMLResponse", singletonList(responseString));

        JwtBuilder jwtBuilder = Jwts.builder().signWith(HS256, getSecretSessionKey()).setExpiration(Date.from(Instant.now().plus(3600, ChronoUnit.SECONDS)));
        jwtBuilder.claim("outboundID", responseId);

        Response result = client
            .property(ClientProperties.FOLLOW_REDIRECTS, false)
            .target(String.format("http://localhost:%d%s", RULE.getLocalPort(), EidasResponseResource.ASSERTION_CONSUMER_PATH))
            .request()
            .cookie("sessionToken", jwtBuilder.compact())
            .buildPost(Entity.form(form))
            .invoke();

        Assert.assertEquals(400, result.getStatus());
    }

    private Key getSecretSessionKey() {
        return Optional.of(SECRET_SEED)
            .map(seed -> Hashing.sha256().newHasher().putString(seed, UTF_8).hash().asBytes())
            .map(k -> (Key) new SecretKeySpec(k, HS256.getJcaName())).get();
    }

}
