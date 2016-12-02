package uk.gov.ida.eidas.bridge.testhelpers;

import com.google.inject.Inject;
import org.opensaml.saml.saml2.core.*;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.domain.AuthnContext;
import uk.gov.ida.saml.hub.HubConstants;
import uk.gov.ida.saml.hub.domain.IdaAuthnRequestFromHub;

public class IdaAuthnRequestFromHubToAuthnRequestTransformer extends IdaAuthnRequestToAuthnRequestTransformer<IdaAuthnRequestFromHub> {

    @Inject
    public IdaAuthnRequestFromHubToAuthnRequestTransformer(OpenSamlXmlObjectFactory samlObjectFactory) {
        super(samlObjectFactory);
    }

    protected void supplementAuthnRequestWithDetails(IdaAuthnRequestFromHub originalRequestFromHub, AuthnRequest authnRequest) {

        Conditions conditions = getSamlObjectFactory().createConditions();
        conditions.setNotOnOrAfter(originalRequestFromHub.getSessionExpiryTimestamp());
        authnRequest.setConditions(conditions);

        Scoping scoping = getSamlObjectFactory().createScoping();
        scoping.setProxyCount(0);
        authnRequest.setScoping(scoping);

        RequestedAuthnContext requestedAuthnContext = getSamlObjectFactory().createRequestedAuthnContext(AuthnContextComparisonTypeEnumeration.MINIMUM);
        AuthnContext minimumLevelOfAssurance = originalRequestFromHub.getMinimumLevelOfAssurance();
        AuthnContext requiredLevelOfAssurance = originalRequestFromHub.getRequiredLevelOfAssurance();

        AuthnContextClassRef minimumAuthnContextClassReference = getSamlObjectFactory().createAuthnContextClassReference(minimumLevelOfAssurance.getUri());
        AuthnContextClassRef requiredAuthnContextClassReference = getSamlObjectFactory().createAuthnContextClassReference(requiredLevelOfAssurance.getUri());
        requestedAuthnContext.getAuthnContextClassRefs().add(requiredAuthnContextClassReference);
        requestedAuthnContext.getAuthnContextClassRefs().add(minimumAuthnContextClassReference);

        NameIDPolicy nameIdPolicy = getSamlObjectFactory().createNameIdPolicy();
        nameIdPolicy.setFormat(NameIDType.PERSISTENT);
        nameIdPolicy.setSPNameQualifier(HubConstants.SP_NAME_QUALIFIER);
        nameIdPolicy.setAllowCreate(true);
        authnRequest.setNameIDPolicy(nameIdPolicy);

        authnRequest.setRequestedAuthnContext(requestedAuthnContext);

        if (originalRequestFromHub.getForceAuthentication().isPresent()) {
            authnRequest.setForceAuthn(originalRequestFromHub.getForceAuthentication().get());
        }
    }

}
