package uk.gov.ida.eidas.bridge.helpers.responseToVerify;

import org.joda.time.DateTime;
import org.joda.time.LocalDate;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.eidas.bridge.helpers.RandomIdGenerator;
import uk.gov.ida.eidas.bridge.helpers.SigningHelper;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.domain.Address;
import uk.gov.ida.saml.core.domain.SimpleMdsValue;
import uk.gov.ida.saml.hub.factories.AttributeFactory;

import java.util.List;

import static com.google.common.base.Optional.absent;
import static java.util.Collections.singletonList;

/**
 * Builds Assertions containing the Verfiy MatchingDataset AttributeStatement.
 *
 * Implementation base on stub-idp-saml's IdentityProviderAssertionToAssertionTransformer.
 *
 */
public class MatchingDatasetAssertionGenerator {
    private final String bridgeEntityId;
    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory;
    private final AttributeFactory attributeFactory;
    private final AssertionSubjectGenerator assertionSubjectGenerator;
    private final SigningHelper signingHelper;

    public MatchingDatasetAssertionGenerator(String bridgeEntityId, OpenSamlXmlObjectFactory openSamlXmlObjectFactory, AttributeFactory attributeFactory, AssertionSubjectGenerator assertionSubjectGenerator, SigningHelper signingHelper) {
        this.bridgeEntityId = bridgeEntityId;
        this.openSamlXmlObjectFactory = openSamlXmlObjectFactory;
        this.attributeFactory = attributeFactory;
        this.assertionSubjectGenerator = assertionSubjectGenerator;
        this.signingHelper = signingHelper;
    }

    public Assertion generate(String inResponseTo, EidasIdentityAssertion eidasIdentityAssertion) throws MarshallingException, SecurityException, SignatureException {
        Assertion assertion = openSamlXmlObjectFactory.createAssertion();

        assertion.setIssueInstant(new DateTime());
        Issuer transformedIssuer = openSamlXmlObjectFactory.createIssuer(bridgeEntityId);
        assertion.setIssuer(transformedIssuer);
        assertion.setID(RandomIdGenerator.generateRandomId());
        assertion.setSubject(assertionSubjectGenerator.generateSubject(inResponseTo, eidasIdentityAssertion.getPersonIdentifier()));
        assertion.getAttributeStatements().add(buildMatchingDatasetAttributeStatement(eidasIdentityAssertion));

        return signingHelper.sign(assertion);
    }

    private AttributeStatement buildMatchingDatasetAttributeStatement(EidasIdentityAssertion eidasIdentityAssertion) {
        AttributeStatement attributeStatement = openSamlXmlObjectFactory.createAttributeStatement();

        Attribute firstnameAttribute = attributeFactory.createFirstnameAttribute(buildMdsValueList(eidasIdentityAssertion.getFirstName()));
        attributeStatement.getAttributes().add(firstnameAttribute);

        Attribute surnameAttribute = attributeFactory.createSurnameAttribute(buildMdsValueList(eidasIdentityAssertion.getFamilyName()));
        attributeStatement.getAttributes().add(surnameAttribute);

        Attribute genderAttribute = attributeFactory.createGenderAttribute(buildMdsValue(eidasIdentityAssertion.getGender()));
        attributeStatement.getAttributes().add(genderAttribute);

        Attribute dateOfBirthAttribute = attributeFactory.createDateOfBirthAttribute(buildMdsValueList(new LocalDate(eidasIdentityAssertion.getDateOfBirth())));
        attributeStatement.getAttributes().add(dateOfBirthAttribute);

        // TODO - the eIDAS stub IdP doesn't provide addresses in a structured form (although the eIDAS spec indicates that it should).
        // As a workaround we're putting the entire, unstructured address that it sends us in the first line of the address and leaving the rest blank.
        Address address = new Address(
            singletonList(eidasIdentityAssertion.getCurrentAddress()),
            absent(),
            absent(),
            absent(),
            null,
            absent(),
            false
        );
        Attribute currentAddressesAttribute = attributeFactory.createCurrentAddressesAttribute(singletonList(address));
        attributeStatement.getAttributes().add(currentAddressesAttribute);

        return attributeStatement;
    }

    private <T> SimpleMdsValue<T> buildMdsValue(T input) {
        return new SimpleMdsValue<>(
            input,
            null, // "From" not required - attributes in eIDAS don't have validity dates
            null, // "To" not required - attributes in eIDAS don't have validity dates
            false // Assume "verified" is false for all eIDAS attributes
        );
    }

    private <T> List<SimpleMdsValue<T>> buildMdsValueList(T input) {
        return singletonList(buildMdsValue(input));
    }
}
