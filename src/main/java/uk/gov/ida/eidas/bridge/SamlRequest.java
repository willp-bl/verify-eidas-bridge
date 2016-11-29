package uk.gov.ida.eidas.bridge;

public class SamlRequest {
    private final String authnRequest;
    private final String singleSignOnLocation;

    public SamlRequest(String authnRequest, String singleSignOnLocation) {
        this.authnRequest = authnRequest;
        this.singleSignOnLocation = singleSignOnLocation;
    }

    public String getAuthnRequest() {
        return authnRequest;
    }

    public String getSingleSignOnLocation() {
        return singleSignOnLocation;
    }
}
