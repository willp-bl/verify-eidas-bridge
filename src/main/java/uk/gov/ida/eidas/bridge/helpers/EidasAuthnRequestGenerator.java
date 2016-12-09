package uk.gov.ida.eidas.bridge.helpers;

import org.joda.time.DateTime;
import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.core.impl.ExtensionsBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.eidas.common.LevelOfAssurance;
import uk.gov.ida.eidas.saml.extensions.NamespaceConstants;
import uk.gov.ida.eidas.saml.extensions.RequestedAttribute;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributeImpl;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributes;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributesImpl;
import uk.gov.ida.eidas.saml.extensions.SPType;
import uk.gov.ida.eidas.saml.extensions.SPTypeImpl;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;

import javax.annotation.Nonnull;

public class EidasAuthnRequestGenerator {
    public static final String PROVIDER_NAME = "PROVIDER_NAME";
    public static final String NATURAL_PERSON_NAME_PREFIX = "http://eidas.europa.eu/attributes/naturalperson/";
    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
    private final XMLObjectBuilderFactory xmlObjectBuilderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
    private final String bridgeEntityId, eidasEntityId;
    private final SigningHelper signingHelper;
    private final SingleSignOnServiceLocator signOnServiceLocator;


    public EidasAuthnRequestGenerator(String bridgeEntityId, String eidasEntityId, SigningHelper signingHelper, SingleSignOnServiceLocator signOnServiceLocator) {
        this.bridgeEntityId = bridgeEntityId;
        this.eidasEntityId = eidasEntityId;
        this.signingHelper = signingHelper;
        this.signOnServiceLocator = signOnServiceLocator;
    }

    public AuthnRequest generateAuthnRequest(String authnReqeustId) throws MarshallingException, SignatureException, SecurityException {
        AuthnRequest eidasAuthnRequest = openSamlXmlObjectFactory.createAuthnRequest();
        Namespace eidasSamlExtensionsNamespace = new Namespace(NamespaceConstants.EIDAS_EXTENSIONS_NAMESPACE, NamespaceConstants.EIDAS_EXTENSIONS_LOCAL_NAME);
        eidasAuthnRequest.getNamespaceManager().registerNamespaceDeclaration(eidasSamlExtensionsNamespace);

        eidasAuthnRequest.setID(authnReqeustId);
        eidasAuthnRequest.setIssueInstant(new DateTime());
        eidasAuthnRequest.setConsent(StatusResponseType.UNSPECIFIED_CONSENT);
        eidasAuthnRequest.setDestination(signOnServiceLocator.getSignOnUrl(eidasEntityId));
        eidasAuthnRequest.setForceAuthn(true);
        eidasAuthnRequest.setProviderName(PROVIDER_NAME);
        eidasAuthnRequest.setIssuer(openSamlXmlObjectFactory.createIssuer(bridgeEntityId));

        NameIDPolicy nameIdPolicy = openSamlXmlObjectFactory.createNameIdPolicy();
        nameIdPolicy.setFormat(NameIDType.UNSPECIFIED);
        nameIdPolicy.setAllowCreate(true);
        eidasAuthnRequest.setNameIDPolicy(nameIdPolicy);

        RequestedAuthnContext requestedAuthnContext = openSamlXmlObjectFactory.createRequestedAuthnContext(AuthnContextComparisonTypeEnumeration.MINIMUM);
        requestedAuthnContext.getAuthnContextClassRefs().add(openSamlXmlObjectFactory.createAuthnContextClassReference(LevelOfAssurance.SUBSTANTIAL.toString()));
        eidasAuthnRequest.setRequestedAuthnContext(requestedAuthnContext);

        Extensions extensions = new ExtensionsBuilder().buildObject();
        eidasAuthnRequest.setExtensions(extensions);

        XMLObjectBuilder<?> spTypeBuilder = xmlObjectBuilderFactory.getBuilder(SPType.DEFAULT_ELEMENT_NAME);
        SPTypeImpl spTypeObject = (SPTypeImpl) spTypeBuilder.buildObject(SPType.DEFAULT_ELEMENT_NAME);
        spTypeObject.setValue("public");
        extensions.getUnknownXMLObjects().add(spTypeObject);

        XMLObjectBuilder<?> requestedAttributesBuilder = xmlObjectBuilderFactory.getBuilder(RequestedAttributes.DEFAULT_ELEMENT_NAME);
        RequestedAttributesImpl requestedAttributesObject = (RequestedAttributesImpl) requestedAttributesBuilder.buildObject(RequestedAttributes.DEFAULT_ELEMENT_NAME);
        requestedAttributesObject.setRequestedAttributes(
            getRequestedAttribute("FirstName", "CurrentGivenName"),
            getRequestedAttribute("FamilyName", "CurrentFamilyName"),
            getRequestedAttribute("DateOfBirth", "DateOfBirth"),
            getRequestedAttribute("CurrentAddress", "CurrentAddress"),
            getRequestedAttribute("PersonIdentifier", "PersonIdentifier"),
            getRequestedAttribute("Gender", "Gender")
        );
        extensions.getUnknownXMLObjects().add(requestedAttributesObject);

        signingHelper.sign(eidasAuthnRequest);

        return eidasAuthnRequest;
    }

    @Nonnull
    private RequestedAttributeImpl getRequestedAttribute(String friendlyName, String nameSuffix) {
        XMLObjectBuilder<?> requestedAttributeBuilder = xmlObjectBuilderFactory.getBuilder(RequestedAttribute.DEFAULT_ELEMENT_NAME);
        RequestedAttributeImpl requestedAttribute = (RequestedAttributeImpl) requestedAttributeBuilder.buildObject(RequestedAttribute.DEFAULT_ELEMENT_NAME);
        requestedAttribute.setName(NATURAL_PERSON_NAME_PREFIX + nameSuffix);
        requestedAttribute.setFriendlyName(friendlyName);
        requestedAttribute.setNameFormat(Attribute.URI_REFERENCE);
        requestedAttribute.setIsRequired(true);
        return requestedAttribute;
    }


}
