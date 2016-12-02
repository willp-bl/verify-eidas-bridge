package uk.gov.ida.eidas.bridge.views;

import io.dropwizard.views.View;

public class ResponseFormView extends View {
    private final String response;
    private final String assertionConsumerLocation;

    public ResponseFormView(String response, String assertionConsumerLocation) {
        super("responseForm.mustache");
        this.response = response;
        this.assertionConsumerLocation = assertionConsumerLocation;
    }

    public String getResponse() {
        return response;
    }

    public String getAssertionConsumerLocation() {
        return assertionConsumerLocation;
    }
}
