package uk.gov.ida.eidas.bridge.views;

import com.google.common.collect.ImmutableList;
import io.dropwizard.views.View;

import java.util.List;
import java.util.Set;

public class ChooseACountryView extends View {
    private Set<String> enabledCountries;

    static class Country {
        private String countryCode;
        private String countryName;
        private String alternativeSpellings;
        private boolean enabled;

        Country(String countryCode, String countryName, String alternativeSpellings, Set<String> enabledCountries) {
            this.countryCode = countryCode;
            this.countryName = countryName;
            this.alternativeSpellings = alternativeSpellings;
            this.enabled = enabledCountries.contains(countryCode);
        }

        public String getCountryCode() {
            return countryCode;
        }

        public String getCountryName() {
            return countryName;
        }

        public String getAlternativeSpellings() {
            return alternativeSpellings;
        }

        public boolean isEnabled() {
            return enabled;
        }
    }

    public ChooseACountryView(Set<String> enabledCountries) {
        super("chooseACountry.mustache");
        this.enabledCountries = enabledCountries;
    }

    public List<Country> getCountries() {
        return ImmutableList.<Country>builder()
            .add(new Country("NL", "Netherlands", "Netherlands Kingdom of the Netherlands NL Nederland", enabledCountries))
            .add(new Country("ES", "Spain", "Spain Kingdom of Spain ES E España Espana", enabledCountries))
            .add(new Country("AT", "Austria", "Austria Republic of Austria AT A Österreich Osterreich", enabledCountries))
            .add(new Country("BE", "Belgium", "Belgium Kingdom of Belgium BE B Belgique België Belgie", enabledCountries))
            .add(new Country("BG", "Bulgaria", "Bulgaria Republic of Bulgaria BG", enabledCountries))
            .add(new Country("HR", "Croatia", "Croatia Republic of Croatia HR Hrvatska", enabledCountries))
            .add(new Country("CY", "Republic", "Cyprus Republic of Cyprus CY", enabledCountries))
            .add(new Country("CZ", "Czech", "Czech Republic Czech Republic CZ Česká republika Ceska republika", enabledCountries))
            .add(new Country("DK", "Denmark", "Denmark Kingdom of Denmark DK DK Danmark", enabledCountries))
            .add(new Country("EE", "Estonia", "Estonia Republic of Estonia EE Eesti", enabledCountries))
            .add(new Country("FI", "Finland", "Finland Republic of Finland FI FIN Suomi Finland", enabledCountries))
            .add(new Country("FR", "France", "France French Republic FR F France", enabledCountries))
            .add(new Country("DE", "Germany", "Germany Federal Republic of Germany DE D Deutschland", enabledCountries))
            .add(new Country("EL", "Greece", "Greece Hellenic Republic EL EL", enabledCountries))
            .add(new Country("HU", "Hungary", "Hungary Hungary HU Magyarország Magyarorszag", enabledCountries))
            .add(new Country("IE", "Ireland", "Ireland Ireland IE IRL Éire Eire Ireland", enabledCountries))
            .add(new Country("IT", "Italy", "Italy Italian Republic IT I Italia", enabledCountries))
            .add(new Country("LV", "Latvia", "Latvia Republic of Latvia LV Latvija", enabledCountries))
            .add(new Country("LT", "Lithuania", "Lithuania Republic of Lithuania LT Lietuva", enabledCountries))
            .add(new Country("LU", "Luxembourg", "Luxembourg Grand Duchy of Luxembourg LU L Luxembourg", enabledCountries))
            .add(new Country("MT", "Malta", "Malta Republic of Malta MT Malta", enabledCountries))
            .add(new Country("NO", "Norway", "Norway Kingdom of Norway NO Norge", enabledCountries))
            .add(new Country("PL", "Poland", "Poland Republic of Poland PL Polska", enabledCountries))
            .add(new Country("PT", "Portugal", "Portugal Portuguese Republic PT P Portugal", enabledCountries))
            .add(new Country("RO", "Romania", "Romania Romania RO România Romania", enabledCountries))
            .add(new Country("SK", "Slovakia", "Slovakia Slovak Republic SK Slovensko", enabledCountries))
            .add(new Country("SI", "Slovenia", "Slovenia Republic of Slovenia SI Slovenija", enabledCountries))
            .add(new Country("SE", "Sweden", "Sweden Kingdom of Sweden SE  S Sverige ", enabledCountries))
            .build();
    }
}
