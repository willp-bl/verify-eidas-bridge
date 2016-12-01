package uk.gov.ida.eidas.bridge.apprule;

import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.client.JerseyClientConfiguration;
import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit.DropwizardAppRule;
import io.dropwizard.util.Duration;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.impl.EntitiesDescriptorUnmarshaller;
import org.w3c.dom.Document;
import uk.gov.ida.eidas.bridge.BridgeApplication;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.factories.VerifyEidasBridgeFactory;
import uk.gov.ida.eidas.bridge.rules.MetadataRule;
import uk.gov.ida.eidas.bridge.testhelpers.TestSigningKeyStoreProvider;
import uk.gov.ida.saml.metadata.test.factories.metadata.EntitiesDescriptorFactory;
import uk.gov.ida.saml.metadata.test.factories.metadata.EntityDescriptorFactory;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;

import javax.ws.rs.client.Client;
import javax.ws.rs.core.Response;

import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;

public class BridgeMetadataIntegrationTest {
    private static Client client;

    private static final String eidasEntityId = "foobar";
    private static final EntityDescriptor eidasEntityDescriptor = new EntityDescriptorFactory().idpEntityDescriptor(eidasEntityId);
    private static final String eidasMetadataPayload = new MetadataFactory().metadata(new EntitiesDescriptorFactory().entitiesDescriptor(singletonList(eidasEntityDescriptor)));


    @ClassRule
    public static final MetadataRule verifyMetadata = MetadataRule.verifyMetadata(new MetadataFactory().defaultMetadata());

    @ClassRule
    public static final MetadataRule eidasMetadata = MetadataRule.eidasMetadata(eidasMetadataPayload);

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
        ConfigOverride.config("hostname", HOSTNAME)
    );

    @BeforeClass
    public static void before() {
        JerseyClientConfiguration configuration = new JerseyClientConfiguration();
        configuration.setTimeout(Duration.microseconds(500));
        client = new JerseyClientBuilder(RULE.getEnvironment()).using(configuration).build("bridge test client");
    }

    @Test
    public void shouldServeMetadata() throws UnmarshallingException {
        Response result = client
            .target(String.format("http://localhost:%d/metadata", RULE.getLocalPort()))
            .request()
            .get();

        assertEquals(Response.Status.OK.getStatusCode(), result.getStatus());

        EntitiesDescriptor entitiesDescriptor = (EntitiesDescriptor) new EntitiesDescriptorUnmarshaller().unmarshall(result.readEntity(Document.class).getDocumentElement());
        Assert.assertNotNull("Should have an entitiesDescriptor", entitiesDescriptor);
    }
}
