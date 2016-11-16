package uk.gov.ida.eidas.bridge.views;

import io.dropwizard.views.View;

public class AuthnRequestFormView extends View {
    private final String authnRequest;

    public AuthnRequestFormView(String authnRequest) {
        super("authnRequestForm.mustache");
        this.authnRequest = authnRequest;
    }

    public String getAuthnRequest() {
        return authnRequest;
    }
}
