<script>
function setFocusThickboxIframe() {
    var iframe = $("#frame")[0];
    iframe.contentWindow.focus();
}

$(document).ready(function(){
      setTimeout("setFocusThickboxIframe()", 100);
});
</script>

<iframe id="frame" src="<?php echo getUrlWithGet('terminal.php'); ?>" style="border-style:solid; height:500px; width:1005px"></iframe> 

