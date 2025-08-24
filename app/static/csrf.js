document.addEventListener('DOMContentLoaded', function(){
  var token = document.querySelector('meta[name="csrf-token"]');
  if(!token){ return; }
  var val = token.getAttribute('content') || '';
  var forms = document.querySelectorAll('form');
  forms.forEach(function(f){
    var method = (f.getAttribute('method') || '').toLowerCase();
    if(method === 'post' || method === 'put' || method === 'patch' || method === 'delete'){
      if(!f.querySelector('input[name="csrf_token"]')){
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'csrf_token';
        input.value = val;
        f.appendChild(input);
      }
    }
  });
});