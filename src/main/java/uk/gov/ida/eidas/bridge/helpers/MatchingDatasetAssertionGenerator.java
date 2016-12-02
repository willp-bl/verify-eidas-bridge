package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationDataBuilder;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;

public class MatchingDatasetAssertionGenerator {
    private final String bridgeEntityId;

    public MatchingDatasetAssertionGenerator(String bridgeEntityId) {
        this.bridgeEntityId = bridgeEntityId;
    }

    public Assertion generate(String inResponseTo, EidasIdentityAssertion eidasIdentityAssertion) {
        Assertion assertion = new AssertionBuilder().buildObject();

        setIssuer(assertion);
        setSubject(inResponseTo, assertion);
        setAttributeStatement(assertion, eidasIdentityAssertion);

        return assertion;
    }

    private void setAttributeStatement(Assertion assertion, EidasIdentityAssertion eidasIdentityAssertion) {
        AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();
        Attribute firstnameAttribute = new AttributeBuilder().buildObject();
        firstnameAttribute.setFriendlyName(eidasIdentityAssertion.getFirstName());
        attributeStatement.getAttributes().add(firstnameAttribute);
        assertion.getAttributeStatements().add(attributeStatement);
    }

    private void setSubject(String inResponseTo, Assertion assertion) {
        Subject subject = new SubjectBuilder().buildObject();
        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();
        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        assertion.setSubject(subject);
    }

    private void setIssuer(Assertion assertion) {
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(bridgeEntityId);
        assertion.setIssuer(issuer);
    }
}
