package uk.gov.ida.eidas.bridge.exceptions;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import org.opensaml.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecurityExceptionMapper implements ExceptionMapper<SecurityException> {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityExceptionMapper.class);

    @Override
    public Response toResponse(SecurityException exception) {
        LOG.error("Security exception", exception);
        return Response.status(Response.Status.BAD_REQUEST).build();
    }
}
