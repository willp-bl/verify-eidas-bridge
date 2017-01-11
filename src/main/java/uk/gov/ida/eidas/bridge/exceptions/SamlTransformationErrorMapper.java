package uk.gov.ida.eidas.bridge.exceptions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class SamlTransformationErrorMapper implements ExceptionMapper<SamlTransformationErrorException> {
    private static final Logger LOG = LoggerFactory.getLogger(SamlTransformationErrorMapper.class);

    @Override
    public Response toResponse(SamlTransformationErrorException exception) {
        LOG.error("SAML transformation exception", exception);

        return Response.status(Response.Status.BAD_REQUEST).build();
    }
}
