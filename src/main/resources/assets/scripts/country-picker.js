(function($){
  function handleSelection(event) {
    event.preventDefault()

    var $countrySelect = $('#country-selector')
    var $countryOption = $countrySelect.find('option[value="' + $countrySelect.val() + '"]')
    var countryName = $countryOption.text()

    if($countryOption.data('enabled')) {
      document.forms[0].submit()
    }
    else if (countryName) {
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
  $('select').selectToAutocomplete()
})(jQuery)
