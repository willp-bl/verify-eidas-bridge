package uk.gov.ida.eidas.bridge.testhelpers;

import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.domain.AuthnContext;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.core.test.builders.SignatureBuilder;
import uk.gov.ida.saml.hub.domain.IdaAuthnRequestFromHub;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

import java.net.URI;
import java.util.Optional;
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
        IdaAuthnRequestFromHub originalRequestFromHub = this.buildFromHub();
        IdaAuthnRequestFromHubToAuthnRequestTransformer transformer = new IdaAuthnRequestFromHubToAuthnRequestTransformer(new OpenSamlXmlObjectFactory());
        AuthnRequest authnRequest = transformer.apply(originalRequestFromHub);

        Signature signature = signatureBuilder.build();
        authnRequest.setSignature(signature);

        //noinspection ConstantConditions
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest).marshall(authnRequest);
        Signer.signObject(signature);

        XmlObjectToBase64EncodedStringTransformer toBase64EncodedStringTransformer = new XmlObjectToBase64EncodedStringTransformer();
        return toBase64EncodedStringTransformer.apply(authnRequest);
    }

    private IdaAuthnRequestFromHub buildFromHub() {
        return new IdaAuthnRequestFromHub(
            id,
            issuer,
            DateTime.now(),
            AuthnContext.LEVEL_1,
            AuthnContext.LEVEL_1,
            Optional.empty(),
            DateTime.now().plusHours(20),
            URI.create("/location"));
    }
}

