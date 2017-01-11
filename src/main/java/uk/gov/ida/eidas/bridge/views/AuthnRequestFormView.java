package uk.gov.ida.eidas.bridge.views;

import io.dropwizard.views.View;

public class AuthnRequestFormView extends View {
    private final String authnRequest;
    private final String singleSignOnLocation;

    public AuthnRequestFormView(String authnRequest, String singleSignOnLocation) {
        super("authnRequestForm.mustache");
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
