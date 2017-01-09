package uk.gov.ida.eidas.bridge.security;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import uk.gov.ida.eidas.bridge.helpers.requestToEidas.CountryNotDefinedException;
import uk.gov.ida.saml.security.SignatureValidator;

import javax.xml.namespace.QName;
import java.util.Map;
import java.util.Optional;

public class MetadataBackedCountrySignatureValidator extends SignatureValidator {
    private final Map<String, ExplicitKeySignatureTrustEngine> countryTrustEngines;

    public MetadataBackedCountrySignatureValidator(Map<String, ExplicitKeySignatureTrustEngine> countryTrustEngines) {
        this.countryTrustEngines = countryTrustEngines;
    }

    @Override
    protected boolean additionalValidations(SignableSAMLObject signableSAMLObject, String entityId, QName role) throws SecurityException {
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIdCriterion(entityId));
        criteriaSet.add(new EntityRoleCriterion(role));

        ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine = Optional.ofNullable(countryTrustEngines.get(entityId)).orElseThrow(CountryNotDefinedException::new);

        return explicitKeySignatureTrustEngine.validate(signableSAMLObject.getSignature(), criteriaSet);
    }
}
