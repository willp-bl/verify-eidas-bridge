package uk.gov.ida.eidas.bridge;

import com.github.tomakehurst.wiremock.WireMockServer;
import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.DropwizardTestSupport;
import io.dropwizard.testing.ResourceHelpers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

public class BridgeApplicationIntegrationTest {

    public static final WireMockServer wireMock = new WireMockServer(wireMockConfig().dynamicPort());

    public static final DropwizardTestSupport<BridgeConfiguration> dropwizardTestSupport = new DropwizardTestSupport<>(BridgeApplication.class,
        ResourceHelpers.resourceFilePath("eidasbridge.yml"),
        ConfigOverride.config("metadata.trustStorePath", ResourceHelpers.resourceFilePath("verify_truststore.ts")),
        ConfigOverride.config("metadata.uri", () -> "http://localhost:" + wireMock.port() + "/SAML2/metadata/federation")
    );

    @Before
    public void before() {
        wireMock.start();
    }

    @After
    public void after() {
        wireMock.stop();
        dropwizardTestSupport.after();
    }

    @Test
    public void shouldRequestMetadataOnStartup() throws Exception {
        wireMock.stubFor(
            get(urlEqualTo("/SAML2/metadata/federation"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/xml")
                    .withBody(new MetadataFactory().defaultMetadata())
                )
        );

        // Start the application
        dropwizardTestSupport.before();

        wireMock.verify(getRequestedFor(urlEqualTo("/SAML2/metadata/federation")));
    }
}
