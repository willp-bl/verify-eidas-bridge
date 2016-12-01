package uk.gov.ida.eidas.bridge.apprule;

import com.github.tomakehurst.wiremock.WireMockServer;
import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.DropwizardTestSupport;
import io.dropwizard.testing.ResourceHelpers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import uk.gov.ida.eidas.bridge.BridgeApplication;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.factories.VerifyEidasBridgeFactory;
import uk.gov.ida.eidas.bridge.testhelpers.TestSigningKeyStoreProvider;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;


public class BridgeApplicationIntegrationTest {

    public static final WireMockServer wireMock = new WireMockServer(wireMockConfig().dynamicPort());

    private static final String KEYSTORE_PASSWORD = "fooBar";
    private static final String encodedSigningKeyStore = TestSigningKeyStoreProvider.getBase64EncodedSigningKeyStore(VerifyEidasBridgeFactory.SIGNING_KEY_ALIAS, KEYSTORE_PASSWORD);
    private static final String encodedEncryptingKeyStore = TestSigningKeyStoreProvider.getBase64EncodedSigningKeyStore(VerifyEidasBridgeFactory.ENCRYPTING_KEY_ALIAS, KEYSTORE_PASSWORD);
    private static final String KEYSTORE_TYPE = "PKCS12";

    public static final DropwizardTestSupport<BridgeConfiguration> dropwizardTestSupport = new DropwizardTestSupport<>(BridgeApplication.class,
        "eidasbridge-test.yml",
        ConfigOverride.config("verifyMetadata.trustStorePath", "test_metadata_truststore.ts"),
        ConfigOverride.config("verifyMetadata.uri", () -> "http://localhost:" + wireMock.port() + "/SAML2/metadata/federation"),
        ConfigOverride.config("eidasMetadata.trustStorePath", "test_metadata_truststore.ts"),
        ConfigOverride.config("eidasMetadata.uri", () -> "http://localhost:" + wireMock.port() + "/ServiceMetadata"),
        ConfigOverride.config("eidasNodeEntityId", "eidasEntityId"),
        ConfigOverride.config("signingKeyStore.base64Value", encodedSigningKeyStore),
        ConfigOverride.config("signingKeyStore.password", KEYSTORE_PASSWORD),
        ConfigOverride.config("signingKeyStore.type", KEYSTORE_TYPE),
        ConfigOverride.config("encryptingKeyStore.base64Value", encodedEncryptingKeyStore),
        ConfigOverride.config("encryptingKeyStore.password", KEYSTORE_PASSWORD),
        ConfigOverride.config("encryptingKeyStore.type", KEYSTORE_TYPE),
        ConfigOverride.config("hostname", "www.example.com")
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
    public void shouldRequestMetadataFromVerifyAndEidasOnStartup() throws Exception {
        wireMock.stubFor(
            get(urlEqualTo("/SAML2/metadata/federation"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/xml")
                    .withBody(new MetadataFactory().defaultMetadata())
                )
        );
        wireMock.stubFor(
            get(urlEqualTo("/ServiceMetadata"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/xml")
                    .withBody(new MetadataFactory().defaultMetadata())
                )
        );

        // Start the application
        dropwizardTestSupport.before();

        wireMock.verify(getRequestedFor(urlEqualTo("/SAML2/metadata/federation")));
        wireMock.verify(getRequestedFor(urlEqualTo("/ServiceMetadata")));
    }
}
