package uk.gov.ida.eidas.bridge;

public class SamlResponse {

    private final String response;
    private final String assertionConsumerUrl;

    public SamlResponse(String response, String assertionConsumerUrl) {
        this.response = response;
        this.assertionConsumerUrl = assertionConsumerUrl;
    }

    public String getResponse() {
        return response;
    }

    public String getAssertionConsumerUrl() {
        return assertionConsumerUrl;
    }
}
