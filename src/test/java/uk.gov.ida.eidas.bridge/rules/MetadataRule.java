package uk.gov.ida.eidas.bridge.rules;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;

public class MetadataRule extends WireMockRule {

    private final String metadata;

    public MetadataRule(String metadata, WireMockConfiguration wireMockConfiguration) {
        super(wireMockConfiguration);
        this.metadata = metadata;
    }

    @Override
    protected void before() {
        super.before();
        this.stubFor(
            get(urlEqualTo("/SAML2/metadata/federation"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/xml")
                    .withBody(metadata)
                )
        );
    }

    public String url() {
        return "http://localhost:" + this.port() + "/SAML2/metadata/federation";
    }

}

