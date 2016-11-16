package uk.gov.ida.eidas.saml.extensions;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import org.opensaml.saml.common.AbstractSAMLObjectBuilder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class RequestedAttributesBuilder extends AbstractSAMLObjectBuilder<RequestedAttributes> {
    @Nonnull
    @Override
    public RequestedAttributes buildObject() {
        return buildObject(NamespaceConstants.EIDAS_EXTENSIONS_NAMESPACE, RequestedAttributes.DEFAULT_ELEMENT_LOCAL_NAME, NamespaceConstants.EIDAS_EXTENSIONS_LOCAL_NAME);
    }

    @Nonnull
    @Override
    public RequestedAttributes buildObject(@Nullable String namespaceURI, @Nonnull @NotEmpty String localName, @Nullable String namespacePrefix) {
        return new RequestedAttributesImpl(namespaceURI, localName, namespacePrefix);
    }
}
