package uk.gov.ida.eidas.bridge.views;

import io.dropwizard.views.View;

public class AuthnRequestFormView extends View {
    private final String authnRequest;
    private final String singleSignOnLocation;
    private final String country;

    public AuthnRequestFormView(String authnRequest, String singleSignOnLocation, String country) {
        super("authnRequestForm.mustache");
        this.authnRequest = authnRequest;
        this.singleSignOnLocation = singleSignOnLocation;
        this.country = country;
    }

    public String getAuthnRequest() {
        return authnRequest;
    }

    public String getSingleSignOnLocation() {
        return singleSignOnLocation;
    }

    public String getCountry() {
        return country;
    }
}
