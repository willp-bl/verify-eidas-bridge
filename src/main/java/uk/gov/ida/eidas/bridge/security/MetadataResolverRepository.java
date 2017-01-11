package uk.gov.ida.eidas.bridge.security;

import org.opensaml.saml.metadata.resolver.MetadataResolver;
import uk.gov.ida.eidas.bridge.exceptions.CountryNotDefinedException;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

public class MetadataResolverRepository {
    private Map<String, MetadataResolver> metadataResolverMap;

    public MetadataResolverRepository(Map<String, MetadataResolver> metadataResolverMap) {
        this.metadataResolverMap = metadataResolverMap;
    }

    public MetadataResolver fetch(String entityId) throws CountryNotDefinedException {
        return Optional.ofNullable(metadataResolverMap.get(entityId)).orElseThrow(() -> new CountryNotDefinedException(entityId));
    }

    public Stream<Map.Entry<String, MetadataResolver>> stream() {
        return metadataResolverMap.entrySet().stream();
    }
}
