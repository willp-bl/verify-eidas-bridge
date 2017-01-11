package uk.gov.ida.eidas.bridge.exceptions;

import org.apache.http.HttpStatus;
import org.glassfish.jersey.message.internal.OutboundJaxrsResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class CountryNotDefinedExceptionMapper implements ExceptionMapper<CountryNotDefinedException>{
    private static final Logger LOG = LoggerFactory.getLogger(CountryNotDefinedExceptionMapper.class);

    @Override
    public Response toResponse(CountryNotDefinedException exception) {
        LOG.error(String.format("Country %s is not defined", exception.getCountry()), exception);
        return OutboundJaxrsResponse.status(HttpStatus.SC_BAD_REQUEST).entity("Country configuration is not defined").build();
    }
}
