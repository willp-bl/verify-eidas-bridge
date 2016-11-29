package uk.gov.ida.eidas.saml.extensions;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.impl.AttributeUnmarshaller;
import org.w3c.dom.Attr;

public class RequestedAttributeUnmarshaller extends AttributeUnmarshaller {

    protected void processAttribute(XMLObject samlObject, Attr attribute) throws UnmarshallingException {
        RequestedAttribute requestedAttribute = (RequestedAttribute) samlObject;
        if (attribute.getLocalName().equals(RequestedAttribute.IS_REQUIRED_ATTRIB_NAME)) {
            requestedAttribute.setIsRequired(Boolean.valueOf(attribute.getValue()));
        } else {
            super.processAttribute(samlObject, attribute);
        }
    }
}

