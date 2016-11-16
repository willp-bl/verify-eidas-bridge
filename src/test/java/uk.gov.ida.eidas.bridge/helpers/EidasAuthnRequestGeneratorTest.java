package uk.gov.ida.eidas.bridge.helpers;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
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
import uk.gov.ida.eidas.common.LevelOfAssurance;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributeImpl;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributes;
import uk.gov.ida.eidas.saml.extensions.SPType;
import uk.gov.ida.eidas.saml.extensions.SPTypeBuilder;
import uk.gov.ida.eidas.saml.extensions.SPTypeImpl;

import javax.xml.namespace.QName;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class EidasAuthnRequestGeneratorTest {

    @Before
    public void bootStrapOpenSaml() {
        EidasSamlBootstrap.bootstrap();
        XMLObjectProviderRegistrySupport.registerObjectProvider(SPType.DEFAULT_ELEMENT_NAME, new SPTypeBuilder(), SPTypeImpl.MARSHALLER, SPTypeImpl.UNMARSHALLER);
    }
    
    @Test
    public void shouldGenerateAnEidasAuthnRequest() {
        String entityId = "http://i.am.the.bridge.com";
        EidasAuthnRequestGenerator earg = new EidasAuthnRequestGenerator(entityId);
        AuthnRequest authnRequest = earg.generateAuthnRequest("aTestId");
        Assert.assertNotNull(authnRequest);
        Assert.assertEquals("aTestId", authnRequest.getID());
        Assert.assertEquals(StatusResponseType.UNSPECIFIED_CONSENT, authnRequest.getConsent());
        Assert.assertEquals(true, authnRequest.isForceAuthn());
        Assert.assertEquals(false, authnRequest.isPassive());
        Assert.assertEquals(SAMLVersion.VERSION_20, authnRequest.getVersion());
        Assert.assertEquals(EidasAuthnRequestGenerator.PROVIDER_NAME, authnRequest.getProviderName());

        Issuer issuer = authnRequest.getIssuer();
        Assert.assertEquals(entityId, issuer.getValue());

        NameIDPolicy nameIDPolicy = authnRequest.getNameIDPolicy();
        Assert.assertEquals(true, nameIDPolicy.getAllowCreate());
        Assert.assertEquals(NameIDType.UNSPECIFIED, nameIDPolicy.getFormat());

        RequestedAuthnContext requestedAuthnContext = authnRequest.getRequestedAuthnContext();
        Assert.assertEquals(AuthnContextComparisonTypeEnumeration.MINIMUM, requestedAuthnContext.getComparison());
        AuthnContextClassRef authnContextClassRef = requestedAuthnContext.getAuthnContextClassRefs().get(0);
        Assert.assertEquals(LevelOfAssurance.SUBSTANTIAL.toString(), authnContextClassRef.getAuthnContextClassRef());

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
    }

    private Map<String, RequestedAttributeImpl> getRequestedAttributesByFriendlyName(List<XMLObject> requestedAttributes) {
        return requestedAttributes.stream()
            .map(x -> (RequestedAttributeImpl)x)
            .collect(Collectors.toMap(AttributeImpl::getFriendlyName, x -> x));
    }
}
