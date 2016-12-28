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
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.duplicates.AttributeFactory;
import uk.gov.ida.eidas.bridge.helpers.RandomIdGenerator;
import uk.gov.ida.eidas.bridge.helpers.SigningHelper;
import uk.gov.ida.saml.core.extensions.IdaAuthnContext;

public class AuthnStatementAssertionGenerator {

    private final String bridgeEntityId;
    private final AttributeFactory attributeFactory;
    private final AssertionSubjectGenerator assertionSubjectGenerator;
    private final SigningHelper signingHelper;


    public AuthnStatementAssertionGenerator(
        String bridgeEntityId,
        AttributeFactory attributeFactory,
        AssertionSubjectGenerator assertionSubjectGenerator, SigningHelper signingHelper) {
        this.bridgeEntityId = bridgeEntityId;
        this.attributeFactory = attributeFactory;
        this.assertionSubjectGenerator = assertionSubjectGenerator;
        this.signingHelper = signingHelper;
    }

    public Assertion generate(String inResponseTo, String ipAddress, String persistentId) throws MarshallingException, SecurityException, SignatureException {
        Assertion assertion = new AssertionBuilder().buildObject();

        assertion.setIssueInstant(new DateTime());
        Issuer transformedIssuer = new IssuerBuilder().buildObject();
        transformedIssuer.setFormat(Issuer.ENTITY);
        transformedIssuer.setValue(bridgeEntityId);
        assertion.setIssuer(transformedIssuer);
        assertion.setID(RandomIdGenerator.generateRandomId());

        assertion.setSubject(assertionSubjectGenerator.generateSubject(inResponseTo, persistentId));

        AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();
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
        AuthnStatement authnStatement = new AuthnStatementBuilder().buildObject();
        AuthnContext authnContext = new AuthnContextBuilder().buildObject();
        AuthnContextClassRef authnContextClassReference = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassReference.setAuthnContextClassRef(IdaAuthnContext.LEVEL_2_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassReference);
        authnStatement.setAuthnContext(authnContext);
        authnStatement.setAuthnInstant(DateTime.now());
        return authnStatement;
    }
}
