package uk.gov.ida.eidas.bridge.domain;

public class EidasSamlResponse {

    private final EidasIdentityAssertion assertion;

    public EidasSamlResponse(EidasIdentityAssertion assertion) {
        this.assertion = assertion;
    }

    public EidasIdentityAssertion getIdentityAssertion() {
        return assertion;
    }
}
