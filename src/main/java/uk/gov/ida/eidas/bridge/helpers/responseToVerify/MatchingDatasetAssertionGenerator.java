package uk.gov.ida.eidas.bridge.helpers.responseToVerify;

import org.joda.time.DateTime;
import org.joda.time.LocalDate;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.duplicates.AttributeFactory;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.eidas.bridge.helpers.RandomIdGenerator;
import uk.gov.ida.eidas.bridge.helpers.SigningHelper;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.extensions.Address;
import uk.gov.ida.saml.core.extensions.Line;
import uk.gov.ida.saml.core.extensions.impl.AddressBuilder;
import uk.gov.ida.saml.core.extensions.impl.LineBuilder;

import static java.util.Collections.singletonList;
import static java.util.Optional.empty;

/**
 * Builds Assertions containing the Verfiy MatchingDataset AttributeStatement.
 *
 * Implementation base on stub-idp-saml's IdentityProviderAssertionToAssertionTransformer.
 *
 */
public class MatchingDatasetAssertionGenerator {
    private final String bridgeEntityId;
    private final AssertionSubjectGenerator assertionSubjectGenerator;
    private final SigningHelper signingHelper;
    private final AttributeFactory attributeFactory;

    public MatchingDatasetAssertionGenerator(String bridgeEntityId, AttributeFactory attributeFactory, AssertionSubjectGenerator assertionSubjectGenerator, SigningHelper signingHelper) {
        this.bridgeEntityId = bridgeEntityId;
        this.attributeFactory = attributeFactory;
        this.assertionSubjectGenerator = assertionSubjectGenerator;
        this.signingHelper = signingHelper;
    }

    public Assertion generate(String inResponseTo, EidasIdentityAssertion eidasIdentityAssertion) throws MarshallingException, SecurityException, SignatureException {
        Assertion assertion = new AssertionBuilder().buildObject();

        assertion.setIssueInstant(new DateTime());
        Issuer transformedIssuer = new IssuerBuilder().buildObject();
        transformedIssuer.setFormat(Issuer.ENTITY);
        transformedIssuer.setValue(bridgeEntityId);
        assertion.setIssuer(transformedIssuer);
        assertion.setID(RandomIdGenerator.generateRandomId());
        assertion.setSubject(assertionSubjectGenerator.generateSubject(inResponseTo, eidasIdentityAssertion.getPersonIdentifier()));
        assertion.getAttributeStatements().add(buildMatchingDatasetAttributeStatement(eidasIdentityAssertion));

        return signingHelper.sign(assertion);
    }

    private AttributeStatement buildMatchingDatasetAttributeStatement(EidasIdentityAssertion eidasIdentityAssertion) {
        AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();

        Attribute firstnameAttribute = attributeFactory.createFirstnameAttribute(singletonList(eidasIdentityAssertion.getFirstName()));
        attributeStatement.getAttributes().add(firstnameAttribute);

        Attribute surnameAttribute = attributeFactory.createSurnameAttribute(singletonList(eidasIdentityAssertion.getFamilyName()));
        attributeStatement.getAttributes().add(surnameAttribute);

        Attribute genderAttribute = attributeFactory.createGenderAttribute(eidasIdentityAssertion.getGender());
        attributeStatement.getAttributes().add(genderAttribute);

        Attribute dateOfBirthAttribute = attributeFactory.createDateOfBirthAttribute(singletonList(new LocalDate(eidasIdentityAssertion.getDateOfBirth())));
        attributeStatement.getAttributes().add(dateOfBirthAttribute);

        Attribute currentAddressesAttribute = new AttributeBuilder().buildObject();
        currentAddressesAttribute.setName(IdaConstants.Attributes_1_1.CurrentAddress.NAME);
        currentAddressesAttribute.setFriendlyName(IdaConstants.Attributes_1_1.CurrentAddress.FRIENDLY_NAME);
        currentAddressesAttribute.setNameFormat(Attribute.UNSPECIFIED);

        // TODO - the eIDAS stub IdP doesn't provide addresses in a structured form (although the eIDAS spec indicates that it should).
        // As a workaround we're putting the entire, unstructured address that it sends us in the first line of the address and leaving the rest blank.
        Line line = new LineBuilder().buildObject();
        line.setValue(eidasIdentityAssertion.getCurrentAddress());

        Address address = new AddressBuilder().buildObject();
        address.getLines().add(line);
        currentAddressesAttribute.getAttributeValues().add(address);

        attributeStatement.getAttributes().add(currentAddressesAttribute);

        return attributeStatement;
    }
}
