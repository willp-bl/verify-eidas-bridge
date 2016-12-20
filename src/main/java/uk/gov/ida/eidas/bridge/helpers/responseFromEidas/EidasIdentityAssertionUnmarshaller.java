package uk.gov.ida.eidas.bridge.helpers.responseFromEidas;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Level;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.saml.core.IdaSamlBootstrap;
import uk.gov.ida.saml.core.domain.Gender;
import uk.gov.ida.saml.core.extensions.StringBasedMdsAttributeValue;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;
import uk.gov.ida.saml.deserializers.validators.Base64StringDecoder;
import uk.gov.ida.saml.security.validators.ValidatedAssertions;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class EidasIdentityAssertionUnmarshaller {
    private static final String NATURAL_PERSON_PREFIX = "http://eidas.europa.eu/attributes/naturalperson/";
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormat.forPattern("YYYY-MM-DD");

    public static final String FIRST_NAME_URI = NATURAL_PERSON_PREFIX + "CurrentGivenName";
    public static final String FAMILY_NAME_URI = NATURAL_PERSON_PREFIX + "CurrentFamilyName";
    public static final String GENDER_URI = NATURAL_PERSON_PREFIX + "Gender";
    public static final String DATE_OF_BIRTH_URI = NATURAL_PERSON_PREFIX + "DateOfBirth";
    public static final String CURRENT_ADDRESS_URI = NATURAL_PERSON_PREFIX + "CurrentAddress";
    public static final String PERSON_IDENTIFIER_URI = NATURAL_PERSON_PREFIX + "PersonIdentifier";

    EidasIdentityAssertion unmarshallAssertion(ValidatedAssertions validatedAssertions) {

        List<Assertion> assertions = validatedAssertions.getAssertions();
        if (assertions.size() != 1) {
            throw new IllegalArgumentException("Expected to find 1 assertion, but found " + assertions.size());
        }
        Assertion assertion = assertions.get(0);

        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        if (attributeStatements.size() != 1) {
            throw new IllegalArgumentException("Expected to find 1 attribute statement, but found " + attributeStatements.size());
        }
        AttributeStatement attributeStatement = attributeStatements.get(0);
        Map<String, String> attributesByName = attributeStatement.getAttributes()
            .stream()
            .collect(Collectors.toMap(Attribute::getName, this::getAttributeValueString));

        return new EidasIdentityAssertion(
            getOrThrow(attributesByName, FIRST_NAME_URI),
            getOrThrow(attributesByName, FAMILY_NAME_URI),
            extractAddressFromBase64EncodedXml(getOrThrow(attributesByName, CURRENT_ADDRESS_URI)),
            Gender.fromString(getOrThrow(attributesByName, GENDER_URI)),
            parseDate(getOrThrow(attributesByName, DATE_OF_BIRTH_URI)),
            getOrThrow(attributesByName, PERSON_IDENTIFIER_URI)
        );
    }

    private DateTime parseDate(String eidasDateString) {
        try {
            return DATE_TIME_FORMATTER.parseDateTime(eidasDateString);
        } catch (IllegalArgumentException ex) {
            throw new SamlTransformationErrorException("Could not parse date " + eidasDateString + " as YYYY-MM-DD.", ex, Level.ERROR);
        }
    }

    /**
     * Section 4.6.9. of the eIDAS technical spec describes how the CurrentAddress element will appear.
     * It claims that it will be a base64 encoded string containing an xml representation of an
     * "eidas:CurrentAddressType".
     *
     * TODO: it seems the stub IdP returns a different kind of XML in its base64 (<eidas-natural:FullCvaddress>)
     */
    private String extractAddressFromBase64EncodedXml(String base64EncodedXmlAddress) {
        String base64DecodedAddressInXMLTag = new Base64StringDecoder().decode(base64EncodedXmlAddress);
        return extractValueFromXMLBlob(base64DecodedAddressInXMLTag);
    }

    private String extractValueFromXMLBlob(String xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new InputSource(new StringReader(xml)));
            Element rootElement = document.getDocumentElement();
            return rootElement.getTextContent();
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new SamlTransformationErrorException("Couldn't extract address from xml blob", e, Level.ERROR);
        }
    }

    private String getAttributeValueString(Attribute attribute) {
        XMLObject attributeValue = attribute.getAttributeValues().stream()
            .filter(this::isLatinScript)
            .findFirst()
            .orElseThrow(() -> new SamlTransformationErrorException("Could not find a Latin value of " + attribute.getName(), Level.ERROR));

        String value = getAttributeValue(attributeValue).getValue();
        if (value == null) {
            throw new IllegalArgumentException("Attribute value had a null value");
        }
        return value;
    }

    private boolean isLatinScript(XMLObject x) {
        Element dom = x.getDOM();
        String latinScriptAttrValue = dom.getAttribute("eidas-natural:LatinScript");
        return Objects.equals(latinScriptAttrValue, "true") || StringUtils.isEmpty(latinScriptAttrValue);
    }

    /**
     * &lt;saml2:AttributeValue&gt; elements should be unmarshalled into instances of StringBasedMdsAttributeValue, as
     * registered in {@link IdaSamlBootstrap#bootstrap()}.
     * @throws SamlTransformationErrorException if the cast fails.
     */
    private StringBasedMdsAttributeValue getAttributeValue(XMLObject xmlObject) {
        try {
            return ((StringBasedMdsAttributeValue) xmlObject);
        }
        catch (ClassCastException ex) {
            throw new SamlTransformationErrorException("Expected XMLObject to be an instance of StringBasedMdsAttributeValue", ex, Level.ERROR);
        }
    }

    private String getOrThrow(Map<String, String> map, String key) {
        String result = map.get(key);
        if (result == null) {
            throw new IllegalArgumentException("Could not find a value for key '" + key + "'");
        }
        return result;
    }

}
