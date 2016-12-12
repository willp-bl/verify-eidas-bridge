package uk.gov.ida.eidas.bridge.helpers;

import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;

public class AssertionSubjectGenerator {
    private final int VALIDITY_PERIOD_MINUTES = 15;
    private final String verifyEntityId;
    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory;

    public AssertionSubjectGenerator(String verifyEntityId, OpenSamlXmlObjectFactory openSamlXmlObjectFactory) {
        this.verifyEntityId = verifyEntityId;
        this.openSamlXmlObjectFactory = openSamlXmlObjectFactory;
    }

    public Subject generateSubject(String inResponseTo, String persistentIdentifier) {
        Subject subject = openSamlXmlObjectFactory.createSubject();

        NameID nameId = openSamlXmlObjectFactory.createNameId(persistentIdentifier);
        nameId.setFormat(NameIDType.PERSISTENT);
        subject.setNameID(nameId);

        SubjectConfirmation subjectConfirmation = openSamlXmlObjectFactory.createSubjectConfirmation();
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData subjectConfirmationData = openSamlXmlObjectFactory.createSubjectConfirmationData();

        subjectConfirmationData.setNotOnOrAfter(new DateTime().plusMinutes(VALIDITY_PERIOD_MINUTES));
        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmationData.setRecipient(verifyEntityId);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        return subject;
    }
}
