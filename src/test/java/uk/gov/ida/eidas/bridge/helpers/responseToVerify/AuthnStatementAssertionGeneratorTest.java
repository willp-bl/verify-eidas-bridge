package uk.gov.ida.eidas.bridge.helpers.responseToVerify;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.duplicates.AttributeFactory;
import uk.gov.ida.eidas.bridge.helpers.EidasSamlBootstrap;
import uk.gov.ida.saml.core.extensions.IPAddress;
import uk.gov.ida.saml.core.extensions.IdaAuthnContext;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static uk.gov.ida.eidas.bridge.testhelpers.SigningHelperBuilder.aSigningHelper;

public class AuthnStatementAssertionGeneratorTest {

    private static final String BRIDGE_ENTITY_ID = "bridgeEntitiyId";
    private static final String VERIFY_ENTITY_ID = "verifyEntityId";

    private static final String IN_RESPONSE_TO = "guid";
    private static final String IP_ADDRESS = "127.0.0.1";
    private static final String PERSON_IDENTIFIER = "aPersonId";

    private AuthnStatementAssertionGenerator authnStatementAssertionGenerator;

    @Before
    public void before() {
        EidasSamlBootstrap.bootstrap();
        authnStatementAssertionGenerator = new AuthnStatementAssertionGenerator(BRIDGE_ENTITY_ID,
            new AttributeFactory(),
            new AssertionSubjectGenerator(VERIFY_ENTITY_ID), aSigningHelper().build());
    }

    @Test
    public void shouldGenerateAnAuthnStatementAssertion() throws MarshallingException, SecurityException, SignatureException {
        assertNotNull(authnStatementAssertionGenerator.generate(IN_RESPONSE_TO, IP_ADDRESS, PERSON_IDENTIFIER));
    }


    @Test
    public void generateIssuerAndSubject() throws Exception {
        Assertion assertion = authnStatementAssertionGenerator.generate(IN_RESPONSE_TO, IP_ADDRESS, PERSON_IDENTIFIER);

        assertEquals(BRIDGE_ENTITY_ID, assertion.getIssuer().getValue());
        Subject subject = assertion.getSubject();
        assertEquals(PERSON_IDENTIFIER, subject.getNameID().getValue());
        List<SubjectConfirmation> subjectConfirmations = subject.getSubjectConfirmations();
        SubjectConfirmation subjectConfirmation = subjectConfirmations.get(0);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
        assertEquals(IN_RESPONSE_TO, subjectConfirmationData.getInResponseTo());

    }

    @Test
    public void generateAttributeStatementWithIpAddress() throws Exception {
        Assertion assertion = authnStatementAssertionGenerator.generate(IN_RESPONSE_TO, IP_ADDRESS, PERSON_IDENTIFIER);
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        assertNotNull(attributeStatements);
        assertTrue(attributeStatements.size() == 1);
        AttributeStatement attributeStatement = attributeStatements.get(0);
        Attribute attribute = attributeStatement.getAttributes().get(0);
        assertNotNull(attribute);
        assertEquals("IPAddress", attribute.getFriendlyName());
        assertEquals("TXN_IPaddress", attribute.getName());
        XMLObject xmlObject = attribute.getAttributeValues().get(0);
        assertNotNull(xmlObject);
        assertTrue(xmlObject instanceof IPAddress);
        IPAddress ipAddress = (IPAddress)xmlObject;
        assertEquals(IP_ADDRESS, ipAddress.getValue());
    }

    @Test
    public void generateLoa2AuthnStatement() throws Exception {
        Assertion assertion = authnStatementAssertionGenerator.generate(IN_RESPONSE_TO, IP_ADDRESS, PERSON_IDENTIFIER);
        List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
        assertNotNull(authnStatements);
        assertTrue(authnStatements.size() == 1);
        AuthnStatement authnStatement = authnStatements.get(0);
        assertEquals(
            IdaAuthnContext.LEVEL_2_AUTHN_CTX,
            authnStatement.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef()
        );
    }

    @Test
    public void shouldSignAssertion() throws Exception {
        Assertion assertion = authnStatementAssertionGenerator.generate(IN_RESPONSE_TO, IP_ADDRESS, PERSON_IDENTIFIER);
        assertNotNull(assertion.getSignature());
    }
}
