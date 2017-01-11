package uk.gov.ida.eidas.bridge.exceptions;

import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class SignatureExceptionMapper implements ExceptionMapper<SignatureException> {
    private static final Logger LOG = LoggerFactory.getLogger(SignatureExceptionMapper.class);

    @Override
    public Response toResponse(SignatureException exception) {
        LOG.error("Signature exception", exception);
        return Response.status(Response.Status.BAD_REQUEST).build();
    }
}
