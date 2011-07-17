$.fn.textWidth = function(){
  var html_org = $(this).html();
  var html_calc = '<span>' + html_org + '</span>'
  $(this).html(html_calc);
  var width = $(this).find('span:first').width();
  $(this).html(html_org);
  return width;
};

var podVisible = true;

function togglePod(lines) {
    var toggle = podVisible ? 'none' : 'block';
    podVisible = !podVisible;
    if (!lines || !lines.length) return;
    for (var i = 0; i < lines.length; i++) {
        var start = lines[i][0],
        length = lines[i][1];
        var sourceC = document.querySelectorAll('.container')[0].children;
        var linesC = document.querySelectorAll('.gutter')[0].children;
        var x;
        for (x = start; x < start + length; x++) {
            sourceC[x].style.display = toggle;
            linesC[x].style.display = toggle;
        }

    }
}

function toggleTOC() {
    var index = $('#index');
    if(!index) return false;
    var visible = index.is(':visible');
    visible ? index.hide() : index.show();
    visible ? $.cookie("hideTOC", 1, { expires: 999, path: '/' }) : $.cookie("hideTOC", 0, { expires: 999, path: '/' });
    return false;
}

$(document).ready(function() {
    SyntaxHighlighter.defaults['quick-code'] = false;
    if(document.location.hash) {
        var lineMatch = document.location.hash.match(/^#L(\d+)$/);
        if( lineMatch ) {
            console.log(lineMatch);
            SyntaxHighlighter.defaults['highlight'] = [lineMatch[1]];
        }
        else {
            var packageMatch = document.location.hash.match(/^#P(\S+)$/);
            if( packageMatch ) {
                var decodedPackageMatch = decodeURIComponent(packageMatch[1]);
                console.log(decodedPackageMatch);
                var re = new RegExp("package " + decodedPackageMatch + ";");
                var source = $("#source").html();
                var leadingSource = source.split(re);
                if( leadingSource.length > 1 ) {
                    var lineCount = leadingSource[0].split("\n").length;
                    SyntaxHighlighter.defaults['highlight'] = [lineCount];
                    document.location.hash = "#L" + lineCount;
                }
                else {
                    document.location.hash = '';
                }
            }
        }
    }

    SyntaxHighlighter.highlight();
    
    $('#signin-button').mouseenter(function(){$('#signin').show()});
    $('#signin').mouseleave(function(){$('#signin').hide()});
    
    $('.author-table').tablesorter({widgets: ['zebra'],textExtraction: function(node){
        if(node.getAttribute('class') == 'date') {
            var date = new Date(node.firstChild.getAttribute('sort'));
            return date.getTime();
        } else {
            return node.innerHTML;
        }
    }} );

    $('.relatize').relatizeDate();

    $('#search-input').keydown(function(event) {
        if (event.keyCode == '13' && event.shiftKey) {
            event.preventDefault();
            document.forms[0].q.name = 'lucky';
            document.forms[0].submit();
        }
    });

    $("#search-input").autocomplete('/search/autocomplete', {
        dataType: 'json',
        delay: 100,
        max: 20,
        selectFirst: false,
        width: $("#search-input").width() + 5,
        parse: function(data) {
            return $.map(data, function(row) {
                return {
                    data: row,
                    value: row.documentation,
                    result: row.documentation
                }
            });
        },
        formatItem: function(item) {
            return item.documentation;
        }
    }).result(function(e, item) {
        document.location.href = '/module/'+ item.documentation;
    });

    var el = $('.search-bar');
    if (!el.length) return;
    var originalTop = el.offset().top; // store original top position
    var height = el.height();
    $(window).scroll(function(e) {
        var screenHeight = $(window).height();
        if ($(this).scrollTop() > originalTop + (screenHeight - height < 0 ? height - screenHeight + 10 : -10 )) {
            el.css({
                'position': 'fixed',
                'top': (screenHeight - height < 0 ? screenHeight - height - 10 : 10 ) + 'px'
            });
        } else {
            el.css({
                'position': 'absolute',
                'top': originalTop
            });
        }
    });

    var items = $('.ellipsis');
      for(var i = 0; i < items.length; i++) {
        var element = $(items[i]);
        var boxWidth = element.width();
        var textWidth = element.textWidth();
        var text = element.text();
        var textLength = text.length;
        if(textWidth <= boxWidth) continue;
        var parts = [text.substr(0, Math.floor(textLength/2)), text.substr(Math.floor(textLength/2), textLength)];
        while(element.textWidth() > boxWidth) {
          if(textLength % 2) {
            parts[0] = parts[0].substr(0, parts[0].length-1);
          } else {
            parts[1] = parts[1].substr(1, parts[1].length);
          }
          textLength--;
          element.html(parts.join('…'));
        }
      }

    $('.pod h1,h2,h3,h4,h5,h6').each(function() {
      $(this).wrap(function() {
        return '<a href="#___pod"></a>';
      });
    });
});

function searchForNearest() {
    document.getElementById('busy').style.visibility = 'visible';
    navigator.geolocation.getCurrentPosition(function(pos) {
        document.location.href = '/mirrors?q=loc:' + pos.coords.latitude + ',' + pos.coords.longitude;
    },
    function() {},
    {
        maximumAge: 600000
    });
}

function disableTag(tag) {
    document.location.href = '/mirrors' + (document.location.search || '?q=') + ' ' + tag;
}

function logInPAUSE(a) {
    if(!a.href.match(/pause/))
        return true;
    var id = prompt('Please enter your PAUSE ID:');
    if(id) document.location.href= a.href + '&id=' +  id;
    return false;
}