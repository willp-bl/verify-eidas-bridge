(function($){
  function handleSelection() {
      event.preventDefault()
      country = document.getElementById("country-selector").value;
      console.log(country)

      //List of countries with eIDAs
      eidasCountries = ["NL", "ES"]

      if(eidasCountries.indexOf(country)  > -1 ) {
          document.forms[0].submit()
      } else {
          document.getElementById('display-noEidas').innerHTML = country
          document.getElementById('noEidas').style.display = "block"
          document.getElementById('hasEidas').style.display = "none"
    }
  }
  $('#user_input').click(handleSelection)
  $(function(){
    $('select').selectToAutocomplete();
  });
})(jQuery);
