package uk.gov.ida.eidas.bridge.views;

import io.dropwizard.views.View;

public class ResponseFormView extends View {
    private final String response;
    private final String assertionConsumerLocation;
    private final String relayState;

    public ResponseFormView(String response, String assertionConsumerLocation, String relayState) {
        super("responseForm.mustache");
        this.response = response;
        this.assertionConsumerLocation = assertionConsumerLocation;
        this.relayState = relayState;
    }

    public String getResponse() {
        return response;
    }

    public String getAssertionConsumerLocation() {
        return assertionConsumerLocation;
    }


    public String getRelayState() {
        return relayState;
    }
}
