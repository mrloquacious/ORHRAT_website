// ***I set the hover function actions in CSS.
//$(document).ready(function() {
  //  $('#get-started-button').hover(
    //    function() {
      //      $(this).toggleClass('hover')
        //});
//});
//$(document).ready(function() {
  //  $('#login-button').hover(
    //    function() {
      //      $(this).toggleClass('hover')
        //});
//});

// How can I open these in new tabs?:

//Did these ever work?  At any rate, some of these are obsolete now, I think?:
/*$(document).ready(function() {
    $('#get-started-button').click(
        function() {
            window.location = "http://www.markortonmusic.com"
        });
});

$(document).ready(function() {
    $('#go-button').click(
        function() {
            window.location = "http://www.markortonmusic.com"
        });
});

$(document).ready(function() {
    $('#password-retrieval-button').click(
        function() {
            window.location = "forgot_password.html"
        });
});

$(document).ready(function() {
    $('#account-creation-button').click(
        function() {
            window.location = "http://www.markortonmusic.com"
        });
});*/

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
}

/* Change this for st4a_score: */
$(document).ready(function(){
/* Keep this.  It's used in the js.cookies plug in: */
/*  var cbox_bool = Cookies.get("cbox_bool") */

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

//$(document).ready(function(){

//    var searchIDs = $('input:checked').map(function(){

//      return $(this).val();

//    });
//    console.log(searchIDs.get());

//});


// Is this necessary, or is it easier to use an <a> in html?:
//$(document).ready(function() {
  //  $('#next-button').click(
    //    function() {
      //      window.location = "what_is_meant.html"
        //});
//});