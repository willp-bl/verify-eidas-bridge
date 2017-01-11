package uk.gov.ida.eidas.bridge.rules;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;

import javax.ws.rs.core.MediaType;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

public class MetadataRule extends WireMockRule {

    private static final String verifyMetadataPath = "/SAML2/metadata/federation";
    private static final String eidasMetadataPath = "/ServiceMetadata";

    private final String path;
    private final MetadataSupplier metadataSupplier;

    private MetadataRule(String path, MetadataSupplier metadataSupplier, WireMockConfiguration wireMockConfiguration) {
        super(wireMockConfiguration);
        this.path = path;
        this.metadataSupplier = metadataSupplier;
    }

    public static MetadataRule eidasMetadata(MetadataSupplier metadataSupplier) {
        return new MetadataRule(eidasMetadataPath, metadataSupplier, wireMockConfig().dynamicPort());
    }

    public static MetadataRule verifyMetadata(MetadataSupplier metadata) {
        return new MetadataRule(verifyMetadataPath, metadata, wireMockConfig().dynamicPort());
    }

    @Override
    protected void before() {
        super.before();
        this.stubFor(
            get(urlEqualTo(path))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", MediaType.APPLICATION_XML)
                    .withBody(metadataSupplier.get(url()))
                )
        );
    }

    public String url() {
        return "http://localhost:" + this.port() + path;
    }
}

