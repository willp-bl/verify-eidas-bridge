package uk.gov.ida.eidas.bridge.helpers.responseToVerify;

import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationDataBuilder;

public class AssertionSubjectGenerator {
    private final int VALIDITY_PERIOD_MINUTES = 15;
    private final String verifyEntityId;

    public AssertionSubjectGenerator(String verifyEntityId) {
        this.verifyEntityId = verifyEntityId;
    }

    public Subject generateSubject(String inResponseTo, String persistentIdentifier) {
        Subject subject = new SubjectBuilder().buildObject();

        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setValue(persistentIdentifier);
        nameId.setFormat(NameIDType.PERSISTENT);
        subject.setNameID(nameId);

        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();

        subjectConfirmationData.setNotOnOrAfter(new DateTime().plusMinutes(VALIDITY_PERIOD_MINUTES));
        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmationData.setRecipient(verifyEntityId);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        return subject;
    }
}
