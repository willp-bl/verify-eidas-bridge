package uk.gov.ida.eidas.bridge.domain;

import org.opensaml.saml.saml2.core.StatusCode;

public class EidasSamlResponse {
    private final EidasIdentityAssertion assertion;
    private final StatusCode failureStatus;

    public EidasSamlResponse(EidasIdentityAssertion assertion) {
        this.assertion = assertion;
        this.failureStatus = null;
    }

    public EidasSamlResponse(StatusCode failureStatus) {
        this.failureStatus = failureStatus;
        this.assertion = null;
    }

    public EidasIdentityAssertion getIdentityAssertion() {
        return assertion;
    }

    public boolean isSuccess() {
        return failureStatus == null;
    }

    public StatusCode getFailureStatus() {
        return failureStatus;
    }
}
