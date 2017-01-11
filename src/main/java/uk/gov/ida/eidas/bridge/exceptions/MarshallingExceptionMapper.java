package uk.gov.ida.eidas.bridge.exceptions;

import org.opensaml.core.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class MarshallingExceptionMapper implements ExceptionMapper<MarshallingException> {
    private static final Logger LOG = LoggerFactory.getLogger(MarshallingExceptionMapper.class);

    @Override
    public Response toResponse(MarshallingException exception) {
        LOG.error("Marshalling exception", exception);
        return Response.status(Response.Status.BAD_REQUEST).build();
    }
}
