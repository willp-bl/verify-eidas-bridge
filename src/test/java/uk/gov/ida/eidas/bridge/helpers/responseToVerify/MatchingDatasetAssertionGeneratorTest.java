package uk.gov.ida.eidas.bridge.helpers.responseToVerify;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import uk.gov.ida.duplicates.AttributeFactory;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.eidas.bridge.domain.Gender;
import uk.gov.ida.eidas.bridge.helpers.EidasSamlBootstrap;
import uk.gov.ida.saml.core.extensions.Address;
import uk.gov.ida.saml.core.extensions.Line;
import uk.gov.ida.saml.core.extensions.StringBasedMdsAttributeValue;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static uk.gov.ida.eidas.bridge.testhelpers.SigningHelperBuilder.aSigningHelper;

public class MatchingDatasetAssertionGeneratorTest {

    private static final String BRIDGE_ENTITY_ID = "bridgeEntityId";
    private static final String VERIFY_ENTITY_ID = "verifyEntityId";
    private static final String IN_RESPONSE_TO = "guid";

    private static final String FAMILY_NAME = "familyName";
    private static final String FIRST_NAME = "aFirstName";
    private static final String CURRENT_ADDRESS = "holborn";
    private static final Gender GENDER = Gender.MALE;
    private static final String DATE_OF_BIRTH = "1965-01-01";
    private static final String PERSON_IDENTIFIER = "anId";

    private MatchingDatasetAssertionGenerator assertionGenerator;

    @Before
    public void before() {
        EidasSamlBootstrap.bootstrap();

        assertionGenerator = new MatchingDatasetAssertionGenerator(BRIDGE_ENTITY_ID,
            new AttributeFactory(),
            new AssertionSubjectGenerator(VERIFY_ENTITY_ID),
            aSigningHelper().build());
    }

    @Test
    public void generateIssuerAndSubject() throws Exception {
        EidasIdentityAssertion eidasIdentityAssertion = new EidasIdentityAssertion(FIRST_NAME, FAMILY_NAME, CURRENT_ADDRESS, GENDER, new DateTime(1965, 1, 1, 0, 0), PERSON_IDENTIFIER);
        Assertion assertion = assertionGenerator.generate(IN_RESPONSE_TO, eidasIdentityAssertion);

        assertEquals(BRIDGE_ENTITY_ID, assertion.getIssuer().getValue());
        Subject subject = assertion.getSubject();
        List<SubjectConfirmation> subjectConfirmations = subject.getSubjectConfirmations();
        SubjectConfirmation subjectConfirmation = subjectConfirmations.get(0);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
        assertEquals(IN_RESPONSE_TO, subjectConfirmationData.getInResponseTo());

    }

    @Test
    public void generateAttributeStatement() throws Exception {
        DateTime dateOfBirth = new DateTime(1965, 1, 1, 0, 0);
        EidasIdentityAssertion eidasIdentityAssertion = new EidasIdentityAssertion(FIRST_NAME, FAMILY_NAME, CURRENT_ADDRESS, GENDER, dateOfBirth, PERSON_IDENTIFIER);

        Assertion assertion = assertionGenerator.generate(IN_RESPONSE_TO, eidasIdentityAssertion);

        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        AttributeStatement attributeStatement = attributeStatements.get(0);
        List<Attribute> attributes = attributeStatement.getAttributes();

        assertEquals(FIRST_NAME, getAttributeValueString(attributes, "MDS_firstname"));
        assertEquals(FAMILY_NAME, getAttributeValueString(attributes, "MDS_surname"));
        assertEquals(GENDER.getValue(), getAttributeValueString(attributes, "MDS_gender"));
        Address currentAddress = (Address) getAttributeValue(attributes, "MDS_currentaddress");
        List<Line> lines = currentAddress.getLines();
        Line line = lines.get(0);
        assertEquals(CURRENT_ADDRESS, line.getValue());
        assertEquals(DATE_OF_BIRTH, getAttributeValueString(attributes, "MDS_dateofbirth"));
    }

    @Test
    public void shouldSignAssertion() throws Exception {
        DateTime dateOfBirth = new DateTime(1965, 1, 1, 0, 0);
        EidasIdentityAssertion eidasIdentityAssertion = new EidasIdentityAssertion(FIRST_NAME, FAMILY_NAME, CURRENT_ADDRESS, GENDER, dateOfBirth, PERSON_IDENTIFIER);

        Assertion assertion = assertionGenerator.generate(IN_RESPONSE_TO, eidasIdentityAssertion);
        assertNotNull(assertion.getSignature());
    }

    private XMLObject getAttributeValue(List<Attribute> attributes, String name) {
        return attributes.stream()
            .filter(x -> x.getName().equals(name))
            .findFirst()
            .flatMap(x -> x.getAttributeValues().stream().findFirst())
            .orElseThrow(() -> new IllegalStateException("Could not find an attribute value for the attribute with name " + name));
    }

    private String getAttributeValueString(List<Attribute> attributes, String name) {
        return ((StringBasedMdsAttributeValue)getAttributeValue(attributes, name)).getValue();
    }


}
