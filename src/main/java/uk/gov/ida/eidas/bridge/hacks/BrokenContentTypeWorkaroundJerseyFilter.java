package uk.gov.ida.eidas.bridge.hacks;

import org.apache.http.HttpHeaders;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientResponseFilter;
import javax.ws.rs.core.MultivaluedMap;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class BrokenContentTypeWorkaroundJerseyFilter implements ClientResponseFilter {
    @Override
    public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext) throws IOException {
        List<String> fixedContentTypeHeaders = new ArrayList<>();
        MultivaluedMap<String, String> headers = responseContext.getHeaders();
        List<String> contentTypeHeaders = headers.get(HttpHeaders.CONTENT_TYPE);

        for (String header : contentTypeHeaders) {
            if (header.startsWith("application;")) {
                // This header is broken. It should have a forward slash (/) before the semicolon
                String fixedHeader = header.replaceFirst("application;", "application/xml;");
                fixedContentTypeHeaders.add(fixedHeader);
            } else {
                fixedContentTypeHeaders.add(header);
            }
        }
        headers.replace(HttpHeaders.CONTENT_TYPE, fixedContentTypeHeaders);
    }
}
