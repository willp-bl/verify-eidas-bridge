package uk.gov.ida.eidas.bridge.domain;

import org.opensaml.saml.saml2.core.StatusCode;
import uk.gov.ida.eidas.common.LevelOfAssurance;

public class EidasSamlResponse {
    private final EidasIdentityAssertion assertion;
    private final StatusCode failureStatus;
    private final LevelOfAssurance levelOfAssurance;

    public EidasSamlResponse(EidasIdentityAssertion assertion, LevelOfAssurance levelOfAssurance) {
        this.assertion = assertion;
        this.failureStatus = null;
        this.levelOfAssurance = levelOfAssurance;
    }

    public EidasSamlResponse(StatusCode failureStatus) {
        this.failureStatus = failureStatus;
        this.assertion = null;
        this.levelOfAssurance = null;
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

    public LevelOfAssurance getLevelOfAssurance() {
        return levelOfAssurance;
    }
}
