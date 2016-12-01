package uk.gov.ida.eidas.bridge.domain;

import org.opensaml.saml.saml2.core.Assertion;
import uk.gov.ida.saml.security.validators.ValidatedAssertions;

import javax.validation.constraints.NotNull;
import java.util.List;

public class EidasSamlResponse {

    private final ValidatedAssertions assertions;

    public EidasSamlResponse(@NotNull ValidatedAssertions assertions) {
        this.assertions = assertions;
    }

    public List<Assertion> getAssertions() {
        return assertions.getAssertions();
    }
}
