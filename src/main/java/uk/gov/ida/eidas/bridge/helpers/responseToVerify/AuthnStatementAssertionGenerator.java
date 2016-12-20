package uk.gov.ida.eidas.bridge.helpers.responseToVerify;

import org.joda.time.DateTime;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.eidas.bridge.helpers.RandomIdGenerator;
import uk.gov.ida.eidas.bridge.helpers.SigningHelper;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.hub.factories.AttributeFactory;

public class AuthnStatementAssertionGenerator {

    private final String bridgeEntityId;
    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory;
    private final AttributeFactory attributeFactory;
    private final AssertionSubjectGenerator assertionSubjectGenerator;
    private final SigningHelper signingHelper;


    public AuthnStatementAssertionGenerator(
        String bridgeEntityId,
        OpenSamlXmlObjectFactory openSamlXmlObjectFactory,
        AttributeFactory attributeFactory,
        AssertionSubjectGenerator assertionSubjectGenerator, SigningHelper signingHelper) {
        this.bridgeEntityId = bridgeEntityId;
        this.openSamlXmlObjectFactory = openSamlXmlObjectFactory;
        this.attributeFactory = attributeFactory;
        this.assertionSubjectGenerator = assertionSubjectGenerator;
        this.signingHelper = signingHelper;
    }

    public Assertion generate(String inResponseTo, String ipAddress, String persistentId) throws MarshallingException, SecurityException, SignatureException {
        Assertion assertion = openSamlXmlObjectFactory.createAssertion();

        assertion.setIssueInstant(new DateTime());
        Issuer transformedIssuer = openSamlXmlObjectFactory.createIssuer(bridgeEntityId);
        assertion.setIssuer(transformedIssuer);
        assertion.setID(RandomIdGenerator.generateRandomId());

        assertion.setSubject(assertionSubjectGenerator.generateSubject(inResponseTo, persistentId));

        AttributeStatement attributeStatement = openSamlXmlObjectFactory.createAttributeStatement();
        Attribute ipAddressAttribute = attributeFactory.createUserIpAddressAttribute(ipAddress);
        attributeStatement.getAttributes().add(ipAddressAttribute);
        assertion.getAttributeStatements().add(attributeStatement);

        assertion.getAuthnStatements().add(buildAuthnStatement());

        return signingHelper.sign(assertion);
    }

    /**
     * This code has been duplicated from stub-idp saml
     * see uk.gov.ida.saml.idp.stub.transformers.outbound.IdentityProviderAuthnStatementToAuthnStatementTransformer#transform
     **/
    private AuthnStatement buildAuthnStatement() {
        AuthnStatement authnStatement = openSamlXmlObjectFactory.createAuthnStatement();
        AuthnContext authnContext = openSamlXmlObjectFactory.createAuthnContext();
        AuthnContextClassRef authnContextClassReference = openSamlXmlObjectFactory.createAuthnContextClassReference(
            uk.gov.ida.saml.core.domain.AuthnContext.LEVEL_2.getUri()
        );
        authnContext.setAuthnContextClassRef(authnContextClassReference);
        authnStatement.setAuthnContext(authnContext);
        authnStatement.setAuthnInstant(DateTime.now());
        return authnStatement;
    }
}
