package uk.gov.ida.eidas.bridge.helpers;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml.saml2.core.AuthnRequest;
import uk.gov.ida.saml.core.IdaSamlBootstrap;

public class EidasAuthnRequestGeneratorTest {
    @Before
    public void bootStrapOpenSaml() {
        IdaSamlBootstrap.bootstrap();
    }
    
    @Test
    public void shouldGenerateAnEidasAuthnRequest() {
        EidasAuthnRequestGenerator earg = new EidasAuthnRequestGenerator();
        AuthnRequest authnRequest = earg.generateAuthnRequest("aTestId");
        Assert.assertNotNull(authnRequest);
        Assert.assertEquals("aTestId", authnRequest.getID());
    }
}
