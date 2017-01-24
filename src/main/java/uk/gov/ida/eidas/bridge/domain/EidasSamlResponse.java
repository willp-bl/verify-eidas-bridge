package uk.gov.ida.eidas.bridge.domain;

import org.opensaml.saml.saml2.core.StatusCode;

public class EidasSamlResponse {
    private final boolean shouldBuildAssertion;
    private final EidasIdentityAssertion assertion;
    private final StatusCode failureStatus;

    public EidasSamlResponse(EidasIdentityAssertion assertion) {
        this.assertion = assertion;
        this.shouldBuildAssertion = true;
        this.failureStatus = null;
    }

    public EidasSamlResponse(StatusCode failureStatus) {
        this.failureStatus = failureStatus;
        this.assertion = null;
        this.shouldBuildAssertion = false;
    }

    public EidasIdentityAssertion getIdentityAssertion() {
        return assertion;
    }

    public boolean shouldBuildAssertion() {
        return shouldBuildAssertion;
    }

    public StatusCode getFailureStatus() {
        return failureStatus;
    }
}
