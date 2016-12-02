package uk.gov.ida.eidas.bridge.helpers;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.saml.core.domain.Gender;

import java.util.List;

import static org.junit.Assert.*;

public class MatchingDatasetAssertionGeneratorTest {

    private static final String BRIDGE_ENTITY_ID = "bridgeEntityId";
    private static final String IN_RESPONSE_TO = "guid";
    private static final String FIRST_NAME = "aFirstName";

    private MatchingDatasetAssertionGenerator mdag;

    @Before
    public void generatorBuild() {
        mdag = new MatchingDatasetAssertionGenerator(BRIDGE_ENTITY_ID);
    }

    @Test
    public void generateIssuerAndSubject() throws Exception {
        EidasIdentityAssertion eidasIdentityAssertion = new EidasIdentityAssertion(FIRST_NAME, "familyName", "holborn", Gender.MALE, new DateTime());
        Assertion assertion = mdag.generate(IN_RESPONSE_TO, eidasIdentityAssertion);

        assertEquals(BRIDGE_ENTITY_ID, assertion.getIssuer().getValue());
        Subject subject = assertion.getSubject();
        List<SubjectConfirmation> subjectConfirmations = subject.getSubjectConfirmations();
        SubjectConfirmation subjectConfirmation = subjectConfirmations.get(0);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
        assertEquals(IN_RESPONSE_TO, subjectConfirmationData.getInResponseTo());

    }

    @Test
    public void generateAttributeStatement() throws Exception {
        EidasIdentityAssertion eidasIdentityAssertion = new EidasIdentityAssertion(FIRST_NAME, "familyName", "holborn", Gender.MALE, new DateTime());
        Assertion assertion = mdag.generate(IN_RESPONSE_TO, eidasIdentityAssertion);

        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        AttributeStatement attributeStatement = attributeStatements.get(0);
        List<Attribute> attributes = attributeStatement.getAttributes();
        Attribute firstAttribute = attributes.get(0);

        assertEquals(FIRST_NAME, firstAttribute.getFriendlyName());

    }


}
