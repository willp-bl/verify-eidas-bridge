package uk.gov.ida.eidas.bridge.exceptions;

import org.opensaml.core.xml.io.MarshallingException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class MarshallingExceptionMapper implements ExceptionMapper<MarshallingException> {
    @Override
    public Response toResponse(MarshallingException exception) {
        return Response.status(Response.Status.BAD_REQUEST).build();
    }
}
