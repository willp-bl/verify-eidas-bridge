package uk.gov.ida.eidas.bridge.resources;

import uk.gov.ida.eidas.bridge.core.Saying;
import uk.gov.ida.eidas.bridge.core.Template;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Optional;
import com.yammer.dropwizard.jersey.caching.CacheControl;
import com.yammer.metrics.annotation.Timed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Path("/bridge")
@Produces(MediaType.APPLICATION_JSON)
public class EidasBridgeResource {
    private static final Logger LOGGER = LoggerFactory.getLogger(EidasBridgeResource.class);

    private final Template template;
    private final AtomicLong counter;

    public EidasBridgeResource(Template template) {
        this.template = template;
        this.counter = new AtomicLong();
    }

    @GET
    @Timed(name = "get-requests")
    @CacheControl(maxAge = 1, maxAgeUnit = TimeUnit.DAYS)
    public Saying sayHello(@QueryParam("name") Optional<String> name) {
        return new Saying(counter.incrementAndGet(), template.render(name));
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response receiveMessageFromConnectorNode(Saying saying) throws JsonProcessingException {
        LOGGER.info("Received from ConnectorNode {}", saying);
        String result = "Received message: " + new ObjectMapper().writeValueAsString(saying);
        return Response.status(200).entity(result).build();
    }
}
