package uk.gov.ida.eidas.bridge.domain;

import org.opensaml.saml.saml2.core.StatusCode;
import uk.gov.ida.eidas.common.LevelOfAssurance;

public class EidasSamlResponse {
    private final EidasIdentityAssertion assertion;
    private final StatusCode failureStatus;
    private final LevelOfAssurance levelOfAssurance;
    private final boolean isSuccess;
    private final String errorMessage;

    public EidasSamlResponse(EidasIdentityAssertion assertion, LevelOfAssurance levelOfAssurance) {
        this.isSuccess = true;
        this.assertion = assertion;
        this.failureStatus = null;
        this.levelOfAssurance = levelOfAssurance;
        this.errorMessage = null;
    }

    public EidasSamlResponse(StatusCode failureStatus, String message) {
        this.isSuccess = false;
        this.failureStatus = failureStatus;
        this.assertion = null;
        this.levelOfAssurance = null;
        this.errorMessage = message;
    }

    public EidasIdentityAssertion getIdentityAssertion() {
        return assertion;
    }

    public boolean isSuccess() {
        return isSuccess;
    }

    public StatusCode getFailureStatus() {
        return failureStatus;
    }

    public LevelOfAssurance getLevelOfAssurance() {
        return levelOfAssurance;
    }

    public String getErrorMessage() { return errorMessage; }
}
