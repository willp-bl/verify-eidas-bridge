package uk.gov.ida.eidas.bridge.testhelpers;

import org.joda.time.DateTime;
import uk.gov.ida.saml.core.domain.AuthnContext;
import uk.gov.ida.saml.core.domain.IdaSamlMessage;

import java.net.URI;
import java.util.Optional;

public class IdaAuthnRequestFromHub extends IdaSamlMessage {
    private AuthnContext minimumLevelOfAssurance;
    private AuthnContext requiredLevelOfAssurance;
    private Optional<Boolean> forceAuthentication;
    private DateTime sessionExpiryTimestamp;

    public IdaAuthnRequestFromHub(
        String id,
        String issuer,
        DateTime issueInstant,
        AuthnContext minimumLevelOfAssurance,
        AuthnContext requiredLevelOfAssurance,
        Optional<Boolean> forceAuthentication,
        DateTime sessionExpiryTimestamp,
        URI idpPostEndpoint) {
        super(id, issuer, issueInstant, idpPostEndpoint);
        this.minimumLevelOfAssurance = minimumLevelOfAssurance;
        this.requiredLevelOfAssurance = requiredLevelOfAssurance;
        this.forceAuthentication = forceAuthentication;
        this.sessionExpiryTimestamp = sessionExpiryTimestamp;
    }

    public AuthnContext getMinimumLevelOfAssurance() {
        return minimumLevelOfAssurance;
    }

    public AuthnContext getRequiredLevelOfAssurance() {
        return requiredLevelOfAssurance;
    }

    public Optional<Boolean> getForceAuthentication() {
        return forceAuthentication;
    }

    public DateTime getSessionExpiryTimestamp() {
        return sessionExpiryTimestamp;
    }
}

