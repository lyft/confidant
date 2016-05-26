// Download index data
$.ajax({
  url: "/confidant/search/lunr-index.json",
  cache: true,
  method: 'GET',
  success: function(data) {
    lunrData = data;
    lunrIndex = lunr.Index.load(lunrData.index);
  }
});

// Setup autocomplete field
$(function() {
  var searchBox = $('#searchbox');
  var searchBoxPosition = searchBox.hasClass('bottom-search') ? { my: "left bottom-11", at: "left top", collision: "flip"} : {};
  searchBox.autocomplete({
    source: function(request, response) {
      if (lunrIndex == null) {
        console.warn("Index not yet loaded")
        return;
      }

      console.warn(request);
      var result = _(lunrIndex.search(request.term)).take(50).pluck('ref').map(function(ref) {
        console.warn(ref);
        return lunrData.docs[ref];
      }).value();

      if (result.length == 0) {
        result = [{'noresults': true}]
      }
      response(result);
    },
    select: function(event, selected) {
      if (!selected.item.noresults) {
        window.location.href = selected.item.url;
      }
    },
    open: function() {
      $(this).removeClass("ui-corner-all").addClass("ui-corner-top");
    },
    close: function() {
      $(this).removeClass("ui-corner-top").addClass("ui-corner-all");
    },
    position: searchBoxPosition
  }).autocomplete().data("ui-autocomplete")._renderItem =  function( ul, item ) {
    // Copied from https://jqueryui.com/autocomplete/#custom-data
    var content = item.noresults
      ? '<span class="noresults">No results found</span>'
      : '<a href="/confidant' + item.url + '">' + item.title + '</a>';

    $(this.menu.element).toggleClass('noresults', !!item.noresults);
    return $("<li>").append(content).appendTo(ul);
  };
});
