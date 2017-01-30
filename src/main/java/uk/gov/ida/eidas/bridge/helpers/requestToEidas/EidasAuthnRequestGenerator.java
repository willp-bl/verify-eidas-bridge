package uk.gov.ida.eidas.bridge.helpers.requestToEidas;

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
import uk.gov.ida.eidas.bridge.helpers.SigningHelper;
import uk.gov.ida.eidas.common.LevelOfAssurance;
import uk.gov.ida.eidas.saml.extensions.NamespaceConstants;
import uk.gov.ida.eidas.saml.extensions.RequestedAttribute;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributeImpl;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributes;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributesImpl;
import uk.gov.ida.eidas.saml.extensions.SPType;
import uk.gov.ida.eidas.saml.extensions.SPTypeImpl;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.domain.AuthnContext;

import javax.annotation.Nonnull;

public class EidasAuthnRequestGenerator {
    public static final String PROVIDER_NAME = "PROVIDER_NAME";
    public static final String NATURAL_PERSON_NAME_PREFIX = "http://eidas.europa.eu/attributes/naturalperson/";
    public static final AuthnContextComparisonTypeEnumeration MINIMUM_AUTHNCONTEXT = AuthnContextComparisonTypeEnumeration.MINIMUM;
    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
    private final XMLObjectBuilderFactory xmlObjectBuilderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
    private final String bridgeEntityId;
    private final SigningHelper signingHelper;
    private final SingleSignOnServiceLocator signOnServiceLocator;


    public EidasAuthnRequestGenerator(String bridgeEntityId, SigningHelper signingHelper, SingleSignOnServiceLocator signOnServiceLocator) {
        this.bridgeEntityId = bridgeEntityId;
        this.signingHelper = signingHelper;
        this.signOnServiceLocator = signOnServiceLocator;
    }

    public AuthnRequest generateAuthnRequest(String authnReqeustId, String destinationEntityId, AuthnContext lowestAuthnContext) throws MarshallingException, SignatureException, SecurityException {
        AuthnRequest eidasAuthnRequest = openSamlXmlObjectFactory.createAuthnRequest();
        Namespace eidasSamlExtensionsNamespace = new Namespace(NamespaceConstants.EIDAS_EXTENSIONS_NAMESPACE, NamespaceConstants.EIDAS_EXTENSIONS_LOCAL_NAME);
        eidasAuthnRequest.getNamespaceManager().registerNamespaceDeclaration(eidasSamlExtensionsNamespace);

        eidasAuthnRequest.setID(authnReqeustId);
        eidasAuthnRequest.setIssueInstant(new DateTime());
        eidasAuthnRequest.setConsent(StatusResponseType.UNSPECIFIED_CONSENT);
        eidasAuthnRequest.setDestination(signOnServiceLocator.getSignOnUrl(destinationEntityId));
        eidasAuthnRequest.setForceAuthn(true);
        eidasAuthnRequest.setProviderName(PROVIDER_NAME);
        eidasAuthnRequest.setIssuer(openSamlXmlObjectFactory.createIssuer(bridgeEntityId));

        NameIDPolicy nameIdPolicy = openSamlXmlObjectFactory.createNameIdPolicy();
        nameIdPolicy.setFormat(NameIDType.UNSPECIFIED);
        nameIdPolicy.setAllowCreate(true);
        eidasAuthnRequest.setNameIDPolicy(nameIdPolicy);

        RequestedAuthnContext requestedAuthnContext = openSamlXmlObjectFactory.createRequestedAuthnContext(MINIMUM_AUTHNCONTEXT);
        String levelOfAssuranceRequested;
        switch (lowestAuthnContext) {
            case LEVEL_1    :   levelOfAssuranceRequested = LevelOfAssurance.LOW.toString();            break;
            case LEVEL_2    :   levelOfAssuranceRequested = LevelOfAssurance.SUBSTANTIAL.toString();    break;
            case LEVEL_3    :   levelOfAssuranceRequested = LevelOfAssurance.HIGH.toString();           break;
            case LEVEL_4    :
            default         :
                throw new SecurityException("Unknown level of assurance from requested AuthnContext : " + lowestAuthnContext);
        }

        requestedAuthnContext.getAuthnContextClassRefs().add(openSamlXmlObjectFactory.createAuthnContextClassReference(levelOfAssuranceRequested));
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
            getRequestedAttribute("FirstName", "CurrentGivenName", true),
            getRequestedAttribute("FamilyName", "CurrentFamilyName", true),
            getRequestedAttribute("DateOfBirth", "DateOfBirth", true),
            getRequestedAttribute("CurrentAddress", "CurrentAddress", false),
            getRequestedAttribute("PersonIdentifier", "PersonIdentifier", true),
            getRequestedAttribute("Gender", "Gender", false)
        );
        extensions.getUnknownXMLObjects().add(requestedAttributesObject);

        signingHelper.sign(eidasAuthnRequest);

        return eidasAuthnRequest;
    }

    @Nonnull
    private RequestedAttributeImpl getRequestedAttribute(String friendlyName, String nameSuffix, boolean required) {
        XMLObjectBuilder<?> requestedAttributeBuilder = xmlObjectBuilderFactory.getBuilder(RequestedAttribute.DEFAULT_ELEMENT_NAME);
        RequestedAttributeImpl requestedAttribute = (RequestedAttributeImpl) requestedAttributeBuilder.buildObject(RequestedAttribute.DEFAULT_ELEMENT_NAME);
        requestedAttribute.setName(NATURAL_PERSON_NAME_PREFIX + nameSuffix);
        requestedAttribute.setFriendlyName(friendlyName);
        requestedAttribute.setNameFormat(Attribute.URI_REFERENCE);
        requestedAttribute.setIsRequired(required);
        return requestedAttribute;
    }


}
