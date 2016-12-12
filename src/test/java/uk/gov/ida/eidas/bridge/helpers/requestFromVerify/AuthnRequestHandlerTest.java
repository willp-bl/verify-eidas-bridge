package uk.gov.ida.eidas.bridge.helpers.requestFromVerify;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.security.SecurityException;
import uk.gov.ida.eidas.bridge.helpers.requestFromVerify.AuthnRequestHandler;
import uk.gov.ida.saml.core.IdaSamlBootstrap;
import uk.gov.ida.saml.core.api.CoreTransformersFactory;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.hub.transformers.inbound.decorators.AuthnRequestSizeValidator;
import uk.gov.ida.saml.hub.validators.StringSizeValidator;
import uk.gov.ida.saml.metadata.MetadataConfiguration;
import uk.gov.ida.saml.security.SignatureValidator;

import javax.xml.namespace.QName;

import static junit.framework.TestCase.assertNotNull;
import static org.mockito.Mockito.when;
import static uk.gov.ida.eidas.bridge.testhelpers.AuthnRequestBuilder.anAuthnRequest;

@RunWith(MockitoJUnitRunner.class)
public class AuthnRequestHandlerTest {

    @Mock
    private MetadataConfiguration configuration;

    private StringToOpenSamlObjectTransformer<AuthnRequest> stringToAuthnRequest = new CoreTransformersFactory()
        .getStringtoOpenSamlObjectTransformer(new AuthnRequestSizeValidator(new StringSizeValidator()));

    @Before
    public void before () {
        when(configuration.getExpectedEntityId()).thenReturn("https://signin.service.gov.uk");
        IdaSamlBootstrap.bootstrap();
    }

    @Test
    public void shouldReturnAuthnRequestWhenSignatureValid() throws Exception {
        AuthnRequestHandler authnRequestHandler = new AuthnRequestHandler(configuration, signatureValidator(true), stringToAuthnRequest);
        AuthnRequest authnRequest = authnRequestHandler.handleAuthnRequest(anAuthnRequest().buildString());
        assertNotNull(authnRequest);
    }

    @Test(expected = SecurityException.class)
    public void shouldThrowSecurityExceptionWhenIssuerIsNotHub() throws Exception {
        AuthnRequestHandler authnRequestHandler = new AuthnRequestHandler(configuration, signatureValidator(true), stringToAuthnRequest);
        authnRequestHandler.handleAuthnRequest(anAuthnRequest().withIssuer("https://not.hub.gov.uk").buildString());
    }

    @Test(expected = SecurityException.class)
    public void shouldThrowSecurityExceptionWhenSignatureInvalid() throws Exception {
        AuthnRequestHandler authnRequestHandler = new AuthnRequestHandler(configuration, signatureValidator(false), stringToAuthnRequest);
        authnRequestHandler.handleAuthnRequest(anAuthnRequest().buildString());
    }

    private SignatureValidator signatureValidator(final boolean validationShouldSucceed) {
        return new SignatureValidator() {
            @Override
            protected boolean additionalValidations(SignableSAMLObject signableSAMLObject, String entityId, QName role) throws SecurityException {
                return validationShouldSucceed;
            }
        };
    }

}
