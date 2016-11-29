package uk.gov.ida.eidas.bridge.helpers;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.core.impl.AttributeImpl;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.eidas.bridge.testhelpers.TestSignatureValidator;
import uk.gov.ida.eidas.common.LevelOfAssurance;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributeImpl;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributes;
import uk.gov.ida.eidas.saml.extensions.SPType;
import uk.gov.ida.eidas.saml.extensions.SPTypeBuilder;
import uk.gov.ida.eidas.saml.extensions.SPTypeImpl;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;

import javax.xml.namespace.QName;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class EidasAuthnRequestGeneratorTest {

    public static final String EIDAS_SSO_LOCATION = "http://eidas/ssoLocation";
    private final String EIDAS_ENTITY_ID = "http://eidas";

    @Mock
    private SingleSignOnServiceLocator singleSignOnServiceLocator;

    @Before
    public void bootStrapOpenSaml() {
        EidasSamlBootstrap.bootstrap();
        XMLObjectProviderRegistrySupport.registerObjectProvider(SPType.DEFAULT_ELEMENT_NAME, new SPTypeBuilder(), SPTypeImpl.MARSHALLER, SPTypeImpl.UNMARSHALLER);
        when(singleSignOnServiceLocator.getSignOnUrl(EIDAS_ENTITY_ID)).thenReturn(EIDAS_SSO_LOCATION);
    }

    @Test
    public void shouldGenerateAnEidasAuthnRequest() throws MarshallingException, SignatureException, SecurityException {
        String entityId = "http://i.am.the.bridge.com";
        EidasAuthnRequestGenerator authnRequestGenerator = createEidasAuthnRequestGenerator(entityId);

        AuthnRequest authnRequest = authnRequestGenerator.generateAuthnRequest("aTestId");
        Assert.assertNotNull(authnRequest);
        Assert.assertNotNull(authnRequest.getIssueInstant());
        Assert.assertEquals(EIDAS_SSO_LOCATION, authnRequest.getDestination());
        Assert.assertEquals("aTestId", authnRequest.getID());
        Assert.assertEquals(StatusResponseType.UNSPECIFIED_CONSENT, authnRequest.getConsent());
        Assert.assertEquals(true, authnRequest.isForceAuthn());
        Assert.assertEquals(false, authnRequest.isPassive());
        Assert.assertEquals(SAMLVersion.VERSION_20, authnRequest.getVersion());
        Assert.assertEquals(EidasAuthnRequestGenerator.PROVIDER_NAME, authnRequest.getProviderName());
    }

    @Test
    public void shouldGenerateAnEidasAuthnRequestIssuer() throws MarshallingException, SignatureException, SecurityException {
        String entityId = "http://i.am.the.bridge.com";
        EidasAuthnRequestGenerator authnRequestGenerator = createEidasAuthnRequestGenerator(entityId);

        AuthnRequest authnRequest = authnRequestGenerator.generateAuthnRequest("aTestId");
        Issuer issuer = authnRequest.getIssuer();
        Assert.assertEquals(entityId, issuer.getValue());
    }

    @Test
    public void shouldGenerateAnEidasAuthnRequestNameIdPolicy() throws MarshallingException, SignatureException, SecurityException {
        String entityId = "http://i.am.the.bridge.com";
        EidasAuthnRequestGenerator authnRequestGenerator = createEidasAuthnRequestGenerator(entityId);

        AuthnRequest authnRequest = authnRequestGenerator.generateAuthnRequest("aTestId");
        NameIDPolicy nameIDPolicy = authnRequest.getNameIDPolicy();
        Assert.assertEquals(true, nameIDPolicy.getAllowCreate());
        Assert.assertEquals(NameIDType.UNSPECIFIED, nameIDPolicy.getFormat());
    }

    @Test
    public void shouldGenerateAnEidasAuthnRequestRequestedAuthnContext() throws MarshallingException, SignatureException, SecurityException {
        String entityId = "http://i.am.the.bridge.com";
        EidasAuthnRequestGenerator authnRequestGenerator = createEidasAuthnRequestGenerator(entityId);

        AuthnRequest authnRequest = authnRequestGenerator.generateAuthnRequest("aTestId");
        RequestedAuthnContext requestedAuthnContext = authnRequest.getRequestedAuthnContext();
        Assert.assertEquals(AuthnContextComparisonTypeEnumeration.MINIMUM, requestedAuthnContext.getComparison());
        AuthnContextClassRef authnContextClassRef = requestedAuthnContext.getAuthnContextClassRefs().get(0);
        Assert.assertEquals(LevelOfAssurance.SUBSTANTIAL.toString(), authnContextClassRef.getAuthnContextClassRef());
    }

    @Test
    public void shouldGenerateAnEidasAuthnRequestExtensions() throws MarshallingException, SignatureException, SecurityException {
        String entityId = "http://i.am.the.bridge.com";
        EidasAuthnRequestGenerator authnRequestGenerator = createEidasAuthnRequestGenerator(entityId);

        AuthnRequest authnRequest = authnRequestGenerator.generateAuthnRequest("aTestId");
        Extensions extensions = authnRequest.getExtensions();
        Assert.assertNotNull(extensions);
        Optional<XMLObject> spType = extensions
            .getUnknownXMLObjects(SPType.DEFAULT_ELEMENT_NAME)
            .stream().findFirst();
        Assert.assertTrue("There should be at least one eidas:SPType element", spType.isPresent());
        XMLObject xmlObject = spType.get();
        Assert.assertTrue("Should be an instance of SPType", xmlObject.getClass().equals(SPTypeImpl.class));
        Assert.assertEquals("public", ((SPTypeImpl) xmlObject).getValue());

        Optional<XMLObject> requestedAttributes = extensions
            .getUnknownXMLObjects(RequestedAttributes.DEFAULT_ELEMENT_NAME)
            .stream().findFirst();

        Assert.assertTrue("There should be at least one eidas:RequestedAttributes", requestedAttributes.isPresent());

        List<XMLObject> requestedAttributeList = requestedAttributes.get().getOrderedChildren();
        Assert.assertTrue("There should be at least one eidas:RequestedAttribute", requestedAttributeList.size() > 0);

        Map<String, RequestedAttributeImpl> reqAttrMap = getRequestedAttributesByFriendlyName(requestedAttributeList);

        RequestedAttributeImpl firstNameRequestedAttribute = reqAttrMap.get("FirstName");
        QName elementQName = firstNameRequestedAttribute.getElementQName();
        Assert.assertEquals("http://eidas.europa.eu/saml-extensions", elementQName.getNamespaceURI());
        Assert.assertEquals("eidas", elementQName.getPrefix());

        Assert.assertNotNull(firstNameRequestedAttribute);
        Assert.assertEquals(EidasAuthnRequestGenerator.NATURAL_PERSON_NAME_PREFIX + "CurrentGivenName", firstNameRequestedAttribute.getName());
        Assert.assertEquals(Attribute.URI_REFERENCE, firstNameRequestedAttribute.getNameFormat());
        Assert.assertEquals(true, firstNameRequestedAttribute.isRequired());

        Assert.assertNotNull(reqAttrMap.get("FamilyName"));
        Assert.assertNotNull(reqAttrMap.get("CurrentAddress"));
        Assert.assertNotNull(reqAttrMap.get("DateOfBirth"));
        Assert.assertNotNull(reqAttrMap.get("PersonIdentifier"));
    }

    @Test
    public void shouldSignTheEidasAuthnRequest() throws MarshallingException, SignatureException, SecurityException {
        String entityId = "http://i.am.the.bridge.com";
        EidasAuthnRequestGenerator authnRequestGenerator = createEidasAuthnRequestGenerator(entityId);
        AuthnRequest authnRequest = authnRequestGenerator.generateAuthnRequest("aTestId");

        Signature signature = authnRequest.getSignature();
        Assert.assertNotNull(signature);
        assertThat(TestSignatureValidator.getSignatureValidator().validate(authnRequest, entityId, SPSSODescriptor.DEFAULT_ELEMENT_NAME)).isTrue();
        Assert.assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, signature.getSignatureAlgorithm());
        Assert.assertNotNull(signature.getKeyInfo());
    }

    private Map<String, RequestedAttributeImpl> getRequestedAttributesByFriendlyName(List<XMLObject> requestedAttributes) {
        return requestedAttributes.stream()
            .map(x -> (RequestedAttributeImpl)x)
            .collect(Collectors.toMap(AttributeImpl::getFriendlyName, x -> x));
    }

    private EidasAuthnRequestGenerator createEidasAuthnRequestGenerator(String entityId) {
        Credential signingCredential = new TestCredentialFactory(TestCertificateStrings.TEST_PUBLIC_CERT, TestCertificateStrings.TEST_PRIVATE_KEY).getSigningCredential();
        Certificate signingCertificate =  new X509CertificateFactory().createCertificate(TestCertificateStrings.TEST_PUBLIC_CERT);
        BasicX509Credential x509SigningCredential = new BasicX509Credential((X509Certificate) signingCertificate);
        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        return new EidasAuthnRequestGenerator(entityId, EIDAS_ENTITY_ID, signingCredential, x509SigningCredential, keyInfoGenerator, singleSignOnServiceLocator);
    }

}
