package uk.gov.ida.eidas.bridge.domain;

import com.google.common.collect.ImmutableMap;
import org.junit.Test;
import uk.gov.ida.eidas.bridge.exceptions.CountryNotDefinedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class CountryRepositoryTest {

    private final String expected = "myEntityId";

    @Test
    public void shouldReturnTheCountryIfItsThere() throws Exception {
        String countryName = "countryA";
        ImmutableMap<String, String> metadataResolverMap = ImmutableMap.of(countryName, expected);
        CountryRepository countryRepository = new CountryRepository(metadataResolverMap);
        assertThat(countryRepository.fetchEntityId(countryName)).isEqualTo(expected);
    }

    @Test
    public void shouldErrorIfTheCountryIsntThere() throws Exception {
        ImmutableMap<String, String> metadataResolverMap = ImmutableMap.of("countryA", expected);
        CountryRepository metadataResolverRepository = new CountryRepository(metadataResolverMap);
        assertThatThrownBy(() -> {metadataResolverRepository.fetchEntityId("countryB");}).isInstanceOf(CountryNotDefinedException.class);
    }
}