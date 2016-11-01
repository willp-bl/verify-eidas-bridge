package uk.gov.ida.eidas.bridge.resources;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/bridge")
@Produces(MediaType.APPLICATION_JSON)
public class EidasBridgeResource {

    @GET
    public Response sayOK() {
        return Response.ok().build();
    }
}
