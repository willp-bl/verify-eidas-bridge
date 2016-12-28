package uk.gov.ida.eidas.bridge.helpers.responseFromEidas;

import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;
import uk.gov.ida.saml.core.validation.SamlValidationSpecificationFailure;
import uk.gov.ida.saml.core.validation.errors.SamlTransformationErrorFactory;
import uk.gov.ida.saml.deserializers.validators.SizeValidator;

public class ResponseSizeValidator implements SizeValidator {
    private static final int LOWER_BOUND = 1400;
    private static final int UPPER_BOUND = 50000;

    @Override
    public void validate(String input) {
        if(input.length() < LOWER_BOUND){
            SamlValidationSpecificationFailure failure = SamlTransformationErrorFactory.stringTooSmall(input.length(), LOWER_BOUND);
            throw new SamlTransformationErrorException(failure.getErrorMessage(), failure.getLogLevel());
        }

        if(input.length() > UPPER_BOUND){
            SamlValidationSpecificationFailure failure = SamlTransformationErrorFactory.stringTooLarge(input.length(), UPPER_BOUND);
            throw new SamlTransformationErrorException(failure.getErrorMessage(), failure.getLogLevel());
        }
    }

}
