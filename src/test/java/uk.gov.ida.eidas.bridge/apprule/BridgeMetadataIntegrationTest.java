package uk.gov.ida.eidas.bridge.apprule;

import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit.DropwizardAppRule;
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
    public static final String KEYSTORE_PASSWORD = "fooBar";

    private static Client client;

    private static final String eidasEntityId = "foobar";
    private static final EntityDescriptor eidasEntityDescriptor = new EntityDescriptorFactory().idpEntityDescriptor(eidasEntityId);
    private static final String eidasMetadataPayload = new MetadataFactory().metadata(new EntitiesDescriptorFactory().entitiesDescriptor(singletonList(eidasEntityDescriptor)));


    @ClassRule
    public static final MetadataRule verifyMetadata = MetadataRule.verifyMetadata(new MetadataFactory().defaultMetadata());

    @ClassRule
    public static final MetadataRule eidasMetadata = MetadataRule.eidasMetadata(eidasMetadataPayload);

    private static final String encodedSigningKeyStore = TestSigningKeyStoreProvider.getBase64EncodedSigningKeyStore(KEYSTORE_PASSWORD);

    public static final String PKCS_12 = "PKCS12";

    private static final String HOSTNAME = "hostname";
    @ClassRule
    public static final DropwizardAppRule<BridgeConfiguration> RULE = new DropwizardAppRule<>(BridgeApplication.class,
        ResourceHelpers.resourceFilePath("eidasbridge.yml"),
        ConfigOverride.config("verifyMetadata.trustStorePath", ResourceHelpers.resourceFilePath("test_metadata_truststore.ts")),
        ConfigOverride.config("verifyMetadata.uri", verifyMetadata::url),
        ConfigOverride.config("eidasMetadata.trustStorePath", ResourceHelpers.resourceFilePath("test_metadata_truststore.ts")),
        ConfigOverride.config("eidasMetadata.uri", eidasMetadata::url),
        ConfigOverride.config("eidasNodeEntityId", eidasEntityId),
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
