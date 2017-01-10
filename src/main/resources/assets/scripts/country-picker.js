(function($){
  function handleSelection() {
    event.preventDefault()

    var $countryOption = $('#country-selector')
    var country = $countryOption.val()
    var countryName = $('option[value="' + country + '"]').text()

    //List of countries with eIDAs
    eidasCountries = ["NL", "ES", "SE"]

    if(eidasCountries.indexOf(country)  > -1 ) {
      document.forms[0].submit()
    } else if (countryName) {
      document.getElementById('display-noEidas').innerHTML = countryName
      document.getElementById('noEidas').style.display = "block"
      document.getElementById('noCountry').style.display = "none"
    }
    else {
      document.getElementById('noEidas').style.display = "none"
      document.getElementById('noCountry').style.display = "block"
    }
  }
  $('#user_input').click(handleSelection)
  $(function(){ $('select').selectToAutocomplete() })
})(jQuery)


