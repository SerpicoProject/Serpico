// Used to search in tables
// credit to http://www.redotheweb.com/2013/05/15/client-side-full-text-search-in-css.html for this
function initSearch() {
  var searchBox = document.getElementById('search');
  var searchStyle = document.getElementById('search_style');

  if (searchBox && searchStyle) {
    // If the page loads with a value already present in the tables,
    // lets run the search right away
    if (searchBox.value) {
      searchStyle.innerHTML = ".searchable:not([data-index*=\"" + searchBox.value.toLowerCase().replace(/</g, '&lt;').replace(/>/g, '&rt;').replace(/"/g, '&quot;') + "\"]) { display: none; }";
    }

    searchBox.addEventListener('input', function() {
      if (!this.value) {
        searchStyle.innerHTML = "";
        return;
      }
      searchStyle.innerHTML = ".searchable:not([data-index*=\"" + this.value.toLowerCase().replace(/</g, '&lt;').replace(/>/g, '&rt;').replace(/"/g, '&quot;') + "\"]) { display: none; }";
    });
  }
}

$(document).ready(function(){
  initSearch();
});

// Used to confirm deletion
function confirmDelete(evt) {
  if (!confirm('Are you sure you want to permanently delete the selected element(s) ?')) {
    evt.preventDefault();
  }
}
$(document).ready(function(){
  var deleteElements = $('a.btn-danger');
  for (var index = 0, length = deleteElements.length; index < length; index++) {
    deleteElements[index].addEventListener('click', confirmDelete, false);
  }
});
//used for managing checkbox with multiple deletion
$(document).ready(function(){
  //manage the box checking all other boxes
  $("#mytable #checkall").click(function () {
    if ($("#mytable #checkall").is(':checked')) {
      $("#mytable input[type=checkbox]").each(function () {
        $(this).prop("checked", true);
      });

    } else {
      $("#mytable input[type=checkbox]").each(function () {
        $(this).prop("checked", false);
      });
    }
  });
  //add the ids to delete to the parameter
  $("[data-toggle=tooltip]").tooltip();
  $("#deletemultiple").click(function () {
    var selected = [];
    $('tbody input:checked[name]').each(function() {
      selected.push($(this).attr('name'));
    });
    if (selected.length == 0 ) {
      alert("You should check at least one attachment name first :-)");
      event.preventDefault();
    } else {
      $(this).attr('href', this.href + selected.join());
    }
  });
});
