package uk.gov.ida.eidas.bridge.exceptions;

import org.opensaml.xmlsec.signature.support.SignatureException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class SignatureExceptionMapper implements ExceptionMapper<SignatureException> {
    @Override
    public Response toResponse(SignatureException exception) {
        return Response.status(Response.Status.BAD_REQUEST).build();
    }
}
