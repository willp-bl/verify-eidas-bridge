package uk.gov.ida.eidas.bridge.security;

import com.google.common.collect.ImmutableMap;
import org.junit.Test;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import uk.gov.ida.eidas.bridge.exceptions.CountryNotDefinedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

public class MetadataResolverRepositoryTest {

    private final MetadataResolver expected = mock(MetadataResolver.class);

    @Test
    public void shouldReturnTheMetadataResolverIfItsThere() throws Exception {
        String countryName = "countryA";
        ImmutableMap<String, MetadataResolver> metadataResolverMap = ImmutableMap.of(countryName, expected);
        MetadataResolverRepository metadataResolverRepository = new MetadataResolverRepository(metadataResolverMap);
        assertThat(metadataResolverRepository.fetch(countryName)).isEqualTo(expected);
    }

    @Test
    public void shouldErrorIfTheMetadataResolverIsntThere() throws Exception {
        ImmutableMap<String, MetadataResolver> metadataResolverMap = ImmutableMap.of("countryA", expected);
        MetadataResolverRepository metadataResolverRepository = new MetadataResolverRepository(metadataResolverMap);
        assertThatThrownBy(() -> {metadataResolverRepository.fetch("countryB");}).isInstanceOf(CountryNotDefinedException.class);
    }
}