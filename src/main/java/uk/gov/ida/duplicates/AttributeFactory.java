package uk.gov.ida.duplicates;

import org.joda.time.LocalDate;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import uk.gov.ida.eidas.bridge.domain.Gender;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.extensions.BaseMdsSamlObject;
import uk.gov.ida.saml.core.extensions.Date;
import uk.gov.ida.saml.core.extensions.PersonName;
import uk.gov.ida.saml.core.extensions.StringValueSamlObject;
import uk.gov.ida.saml.core.extensions.impl.DateBuilder;
import uk.gov.ida.saml.core.extensions.impl.GenderBuilder;
import uk.gov.ida.saml.core.extensions.impl.IPAddressBuilder;
import uk.gov.ida.saml.core.extensions.impl.PersonNameBuilder;

import java.util.List;
import java.util.stream.Collectors;

import static java.util.Collections.singletonList;

/**
 * Adapted from {@link uk.gov.ida.saml.hub.factories.AttributeFactory_1_1} which lives in saml-utils.
 */
public class AttributeFactory {

    public Attribute createFirstnameAttribute(List<String> firstnames) {
        return createPersonNameAttribute(firstnames, IdaConstants.Attributes_1_1.Firstname.NAME, IdaConstants.Attributes_1_1.Firstname.FRIENDLY_NAME);
    }

    public Attribute createSurnameAttribute(List<String> surnames) {
        return createPersonNameAttribute(surnames, IdaConstants.Attributes_1_1.Surname.NAME, IdaConstants.Attributes_1_1.Surname.FRIENDLY_NAME);
    }

    public Attribute createGenderAttribute(Gender gender) {
        final uk.gov.ida.saml.core.extensions.Gender genderValue = new GenderBuilder().buildObject();
        genderValue.setValue(gender.getValue());

        setVerifyMdsAttributes(genderValue);

        return createAttribute(
            IdaConstants.Attributes_1_1.Gender.NAME,
            IdaConstants.Attributes_1_1.Gender.FRIENDLY_NAME,
            singletonList((AttributeValue) genderValue));
    }

    public Attribute createDateOfBirthAttribute(List<LocalDate> dateOfBirths) {
        return createAttribute(
            IdaConstants.Attributes_1_1.DateOfBirth.NAME,
            IdaConstants.Attributes_1_1.DateOfBirth.FRIENDLY_NAME,
            createAttributeValuesForDate(dateOfBirths)
        );
    }

    public Attribute createUserIpAddressAttribute(String userIpAddressString) {
        final StringValueSamlObject ipAddress = new IPAddressBuilder().buildObject();
        ipAddress.setValue(userIpAddressString);

        return createAttribute(
            IdaConstants.Attributes_1_1.IPAddress.NAME,
            IdaConstants.Attributes_1_1.IPAddress.FRIENDLY_NAME,
            singletonList(ipAddress)
        );
    }

    private Attribute createPersonNameAttribute(final List<String> names, final String attributeName, final String attributeFriendlyName) {
        List<AttributeValue> personNameAttributeValues = createAttributeValuesForPersonName(names);
        return createAttribute(
            attributeName,
            attributeFriendlyName,
            personNameAttributeValues
        );
    }

    private Attribute createAttribute(
        String attributeName,
        String attributeFriendlyName,
        List<? extends XMLObject> attributeValues) {
        Attribute nameAttribute = new AttributeBuilder().buildObject();

        nameAttribute.setName(attributeName);
        nameAttribute.setFriendlyName(attributeFriendlyName);
        nameAttribute.setNameFormat(Attribute.UNSPECIFIED);
        nameAttribute.getAttributeValues().addAll(attributeValues);

        return nameAttribute;
    }

    private List<AttributeValue> createAttributeValuesForPersonName(List<String> nameValues) {
        return nameValues.stream().map(this::createAttributeValueForPersonName).collect(Collectors.toList());
    }

    private List<AttributeValue> createAttributeValuesForDate(List<LocalDate> dateValues) {
        return dateValues.stream().map(this::createAttributeValueForDate).collect(Collectors.toList());
    }

    private PersonName createAttributeValueForPersonName(String value) {
        final PersonName personNameAttributeValue = new PersonNameBuilder().buildObject();
        personNameAttributeValue.setValue(value);
        personNameAttributeValue.setLanguage(IdaConstants.IDA_LANGUAGE);
        setVerifyMdsAttributes(personNameAttributeValue);
        return personNameAttributeValue;
    }

    private Date createAttributeValueForDate(LocalDate value) {
        Date dateAttributeValue = new DateBuilder().buildObject();
        dateAttributeValue.setValue(value.toString("yyyy-MM-dd"));
        setVerifyMdsAttributes(dateAttributeValue);
        return dateAttributeValue;
    }

    private void setVerifyMdsAttributes(BaseMdsSamlObject samlObject) {
        samlObject.setFrom(null);      // "From" not required - attributes in eIDAS don't have validity dates
        samlObject.setTo(null);        // "To" not required - attributes in eIDAS don't have validity dates
        samlObject.setVerified(false); // Assume "verified" is false for all eIDAS attributes
    }
}
