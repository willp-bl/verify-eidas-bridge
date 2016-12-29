package uk.gov.ida.eidas.bridge.testhelpers;

import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.Scoping;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.ScopingBuilder;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import uk.gov.ida.saml.core.extensions.IdaAuthnContext;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.core.test.builders.SignatureBuilder;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

import java.util.UUID;

import static uk.gov.ida.saml.core.test.builders.SignatureBuilder.aSignature;

public class AuthnRequestBuilder {
    private String issuer = "https://signin.service.gov.uk";
    private SignatureBuilder signatureBuilder = aSignature();
    private String id = UUID.randomUUID().toString();

    public static AuthnRequestBuilder anAuthnRequest() {
        return new AuthnRequestBuilder();
    }

    public AuthnRequestBuilder withIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public AuthnRequestBuilder withID(String id) {
        this.id = id;
        return this;
    }

    public AuthnRequestBuilder withSigningCredentials(String signingCertificate, String signingKey) {
        signatureBuilder = signatureBuilder.withSigningCredential(
            new TestCredentialFactory(signingCertificate, signingKey).getSigningCredential()
        );
        return this;
    }

    public String buildString() throws MarshallingException, SignatureException {
        AuthnRequest authnRequest = createAuthnRequest();

        Signature signature = signatureBuilder.build();
        authnRequest.setSignature(signature);

        //noinspection ConstantConditions
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest).marshall(authnRequest);
        Signer.signObject(signature);

        XmlObjectToBase64EncodedStringTransformer toBase64EncodedStringTransformer = new XmlObjectToBase64EncodedStringTransformer();
        return toBase64EncodedStringTransformer.apply(authnRequest);
    }

    private AuthnRequest createAuthnRequest() {
        AuthnRequest authnRequest = new org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder().buildObject();
        authnRequest.setID(id);
        authnRequest.setIssueInstant(DateTime.now());
        authnRequest.setDestination("/location");
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);

        Issuer theIssuer = new IssuerBuilder().buildObject();
        theIssuer.setValue(issuer);
        authnRequest.setIssuer(theIssuer);

        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotOnOrAfter(DateTime.now().plusHours(20));
        authnRequest.setConditions(conditions);

        Scoping scoping = new ScopingBuilder().buildObject();
        scoping.setProxyCount(0);
        authnRequest.setScoping(scoping);

        RequestedAuthnContext requestedAuthnContext = new RequestedAuthnContextBuilder().buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        AuthnContextClassRef minimumAuthnContextClassReference = new AuthnContextClassRefBuilder().buildObject();
        minimumAuthnContextClassReference.setAuthnContextClassRef(IdaAuthnContext.LEVEL_1_AUTHN_CTX);
        AuthnContextClassRef requiredAuthnContextClassReference = new AuthnContextClassRefBuilder().buildObject();
        requiredAuthnContextClassReference.setAuthnContextClassRef(IdaAuthnContext.LEVEL_2_AUTHN_CTX);
        requestedAuthnContext.getAuthnContextClassRefs().add(requiredAuthnContextClassReference);
        requestedAuthnContext.getAuthnContextClassRefs().add(minimumAuthnContextClassReference);

        NameIDPolicy nameIdPolicy = new NameIDPolicyBuilder().buildObject();
        nameIdPolicy.setFormat(NameIDType.PERSISTENT);
        nameIdPolicy.setSPNameQualifier("https://hub.gov.uk");
        nameIdPolicy.setAllowCreate(true);
        authnRequest.setNameIDPolicy(nameIdPolicy);

        authnRequest.setRequestedAuthnContext(requestedAuthnContext);
        return authnRequest;
    }
}

