package uk.gov.ida.eidas.bridge.rules;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;

import javax.ws.rs.core.MediaType;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;

public class MetadataRule extends WireMockRule {

    private final String metadata;
    private final String verifyMetadataPath = "/SAML2/metadata/federation";
    private final String eidasMetadataPath = "/ServiceMetadata";

    public MetadataRule(String metadata, WireMockConfiguration wireMockConfiguration) {
        super(wireMockConfiguration);
        this.metadata = metadata;
    }

    @Override
    protected void before() {
        super.before();
        this.stubFor(
            get(urlEqualTo(verifyMetadataPath))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", MediaType.APPLICATION_XML)
                    .withBody(metadata)
                )
        );
        this.stubFor(
            get(urlEqualTo(eidasMetadataPath))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", MediaType.APPLICATION_XML)
                    .withBody(metadata)
                )
        );
    }

    public String verifyUrl() {
        return "http://localhost:" + this.port() + verifyMetadataPath;
    }

    public String eidasUrl() {
        return "http://localhost:" + this.port() + eidasMetadataPath;
    }

}

