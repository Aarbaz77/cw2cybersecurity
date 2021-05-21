$("input:text").bind('keypress blur', function() {
  $(this).val(
             $(this).val().replace(/[^A-Za-z0-9\s]/g,'')
             )

});
