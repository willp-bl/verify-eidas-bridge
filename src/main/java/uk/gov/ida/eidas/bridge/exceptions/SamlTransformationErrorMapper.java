package uk.gov.ida.eidas.bridge.exceptions;

import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class SamlTransformationErrorMapper implements ExceptionMapper<SamlTransformationErrorException> {
    @Override
    public Response toResponse(SamlTransformationErrorException exception) {
        return Response.status(Response.Status.BAD_REQUEST).build();
    }
}
