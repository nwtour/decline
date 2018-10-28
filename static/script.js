function one_percent() {
   return ( document.documentElement.clientWidth / 100 );
}

function static_onload() {
   var percent  = one_percent ();
   document.getElementById('logo').setAttribute("style","width:" + ( percent * 10 ) + "px; height:" + ( percent * 10 ) + "px");
   if (document.getElementById('base')) {
      document.getElementById('base').style.top = ( percent * 5 ) + "px";
   }
   if (document.getElementById('right')) {
      document.getElementById('right').style.top = ( percent * 5 ) + "px";
   }
   if (document.getElementById('altitude5')) {
      document.getElementById('altitude5').setAttribute("style","width:" + (one_percent() * 4) + "px; height:" + (one_percent() * 4) + "px");
   }

   var x = document.getElementsByClassName("resize_img_4percent");
   for (i = 0; i < x.length; i++) {
      x[i].setAttribute("style","width:" + (percent * 4) + "px; height:" + (percent * 4) + "px");
   }

   if (document.getElementById('div_content')) {
      document.getElementById("div_content").style.visibility = "visible";
   }

   send_request ();
}

function send_request() {

   document.getElementById('updates_proccess').innerHTML = '<img border="0" src="/static/loading.gif">';

   var req = new XMLHttpRequest();
   req.onreadystatechange = function() {  
      if (req.readyState == 4) { 
         if(req.status == 200 && req.responseText != '') { 
            document.getElementById('updates').innerHTML = 'Обмен данными ' + req.responseText;
         }
         document.getElementById('updates_proccess').innerHTML = '';
      }
   }
   req.open('GET', '/public/update', true);  
   req.send(null);
   setTimeout(send_request, 5000);
}
