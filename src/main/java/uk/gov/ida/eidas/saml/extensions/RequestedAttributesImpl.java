package uk.gov.ida.eidas.saml.extensions;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.common.AbstractSAMLObject;
import org.opensaml.saml.common.AbstractSAMLObjectMarshaller;
import org.opensaml.saml.common.AbstractSAMLObjectUnmarshaller;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.List;

public class RequestedAttributesImpl extends AbstractSAMLObject implements RequestedAttributes {

    public static final Marshaller MARSHALLER = new AbstractSAMLObjectMarshaller() { };
    public static final Unmarshaller UNMARSHALLER = new AbstractSAMLObjectUnmarshaller() { };

    private XMLObject[] requestedAttributeObjects = new XMLObject[]{};

    RequestedAttributesImpl(@Nullable String namespaceURI, @Nonnull String elementLocalName, @Nullable String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    @Nullable
    @Override
    public List<XMLObject> getOrderedChildren() {
        return Arrays.asList(requestedAttributeObjects);
    }

    public void setRequestedAttributes(RequestedAttribute... requestedAttribute) {
        this.requestedAttributeObjects = requestedAttribute;
    }
}
