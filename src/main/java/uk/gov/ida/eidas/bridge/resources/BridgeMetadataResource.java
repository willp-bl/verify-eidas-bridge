package uk.gov.ida.eidas.bridge.resources;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
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
    private final Function<EntitiesDescriptor, Element> entitiesDescriptorElementTransformer;

    public BridgeMetadataResource(
        BridgeMetadataGenerator bridgeMetadataGenerator,
        Function<EntitiesDescriptor, Element> entitiesDescriptorElementTransformer) {
        this.bridgeMetadataGenerator = bridgeMetadataGenerator;
        this.entitiesDescriptorElementTransformer = entitiesDescriptorElementTransformer;
    }

    @GET
    @Path("/metadata")
    public Document getMetadata() throws SignatureException, MarshallingException {
        EntitiesDescriptor entitiesDescriptor = bridgeMetadataGenerator.generateMetadata();
        return entitiesDescriptorElementTransformer.apply(entitiesDescriptor).getOwnerDocument();
    }
}
