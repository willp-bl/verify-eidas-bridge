package uk.gov.ida.eidas.bridge.resources;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import uk.gov.ida.eidas.bridge.helpers.BridgeMetadataGenerator;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.function.Function;

@Path("/")
@Produces(MediaType.APPLICATION_XML)
public class BridgeMetadataResource {
    private final BridgeMetadataGenerator bridgeMetadataGenerator;
    private final Function<EntityDescriptor, Element> entityDescriptorElementTransformer;

    public BridgeMetadataResource(
        BridgeMetadataGenerator bridgeMetadataGenerator,
        Function<EntityDescriptor, Element> entityDescriptorElementTransformer) {
        this.bridgeMetadataGenerator = bridgeMetadataGenerator;
        this.entityDescriptorElementTransformer = entityDescriptorElementTransformer;
    }

    @GET
    @Path("/metadata")
    public Document getMetadata() throws SignatureException, MarshallingException, SecurityException {
        EntityDescriptor entityDescriptor = bridgeMetadataGenerator.createEntityDescriptor();
        return entityDescriptorElementTransformer.apply(entityDescriptor).getOwnerDocument();
    }
}
