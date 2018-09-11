
function checkThis() {
    var numberChecked = document.querySelectorAll('input:checked').length;
    document.getElementById('you-marked-number').innerHTML = numberChecked;

    if (numberChecked === 0)
    {
      document.getElementById('your-score-number').innerHTML = 0
    }

    else if (numberChecked > 0 && numberChecked < 8)
    {
      document.getElementById('your-score-number').innerHTML = 1
    }

    else if (numberChecked > 7 && numberChecked < 14)
    {
      document.getElementById('your-score-number').innerHTML = 2
    }

    else if (numberChecked > 13 && numberChecked < 21)
    {
      document.getElementById('your-score-number').innerHTML = 3
    }

    else if (numberChecked > 20)
    {
      document.getElementById('your-score-number').innerHTML = 4
    }

    document.write(numberChecked);
}

/* Change this for st4a_score: */
$(document).ready(function(){
/* Keep this.  It's used in the js.cookies plug in: */
var cbox_bool = Cookies.get("cbox_bool")

  var st4a_score = $.cookie("st4a_score")

  if (st4a_score) {
    $('#st4a-r-and-e').css('visibility', 'visible');
    $('#st4b-r-and-e').css('visibility', 'visible');
    $('#start-standard4-button-box').css('visibility', 'hidden');
    /* What's with this?: */
    $('#st4-score').css('display', 'inline');
  };
});

$( ":checkbox" )
  .map(function() {
    return this.id;
  })
  .get()
  .join();