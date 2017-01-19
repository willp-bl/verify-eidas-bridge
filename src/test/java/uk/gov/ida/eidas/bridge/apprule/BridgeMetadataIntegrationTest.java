package uk.gov.ida.eidas.bridge.apprule;

import com.google.common.collect.ImmutableMap;
import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.testing.junit.DropwizardAppRule;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.impl.EntitiesDescriptorUnmarshaller;
import org.w3c.dom.Document;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.rules.BridgeAppRule;
import uk.gov.ida.eidas.bridge.rules.MetadataRule;
import uk.gov.ida.eidas.bridge.testhelpers.NodeMetadataFactory;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;

import javax.ws.rs.client.Client;
import javax.ws.rs.core.Response;
import java.util.Map;
import java.util.function.Supplier;

import static org.junit.Assert.assertEquals;

public class BridgeMetadataIntegrationTest {
    private static Client client;

    @ClassRule
    public static final MetadataRule verifyMetadata = MetadataRule.verifyMetadata(uri-> new MetadataFactory().defaultMetadata());

    @ClassRule
    public static final MetadataRule eidasMetadata = MetadataRule.eidasMetadata(NodeMetadataFactory::createNodeIdpMetadata);

    private static Map<String, Supplier<String>> countryConfig = ImmutableMap.of("FR", eidasMetadata::url, "ES", () -> "http://some-metadata.com");

    @ClassRule
    public static final DropwizardAppRule<BridgeConfiguration> RULE = BridgeAppRule.createBridgeAppRule(verifyMetadata::url, countryConfig);

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
