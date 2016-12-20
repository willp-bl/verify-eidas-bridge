package uk.gov.ida.eidas.bridge.exceptions;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import org.opensaml.security.SecurityException;

public class SecurityExceptionMapper implements ExceptionMapper<SecurityException> {
    @Override
    public Response toResponse(SecurityException exception) {
        return Response.status(Response.Status.BAD_REQUEST).build();
    }
}
