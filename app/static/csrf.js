// app/static/csrf.js
document.addEventListener('DOMContentLoaded', function () {
  var meta = document.querySelector('meta[name="csrf-token"]');
  var token = meta ? meta.getAttribute('content') : '';

  // 1) Injecter un <input name="csrf_token"> dans tous les forms mutateurs
  document.querySelectorAll('form').forEach(function (f) {
    var method = (f.getAttribute('method') || '').toLowerCase();
    if (['post', 'put', 'patch', 'delete'].includes(method)) {
      if (!f.querySelector('input[name="csrf_token"]')) {
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'csrf_token';
        input.value = token;
        f.appendChild(input);
      }
    }
  });

  // 2) Enrichir window.fetch pour ajouter le header CSRF aux requêtes mutatrices same-origin
  var _fetch = window.fetch;
  window.fetch = function (input, init) {
    init = init || {};
    var method = (init.method || 'GET').toUpperCase();
    var isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
    var url = (typeof input === 'string') ? input : (input.url || '');

    // Même origine ?
    var sameOrigin = true;
    try {
      var u = new URL(url, window.location.origin);
      sameOrigin = (u.origin === window.location.origin);
    } catch (e) { /* relative URL => même origine */ }

    if (isMutating && sameOrigin) {
      init.headers = init.headers || {};
      if (init.headers instanceof Headers) {
        init.headers.set('X-CSRFToken', token);
        init.headers.set('X-CSRF-Token', token);
      } else if (Array.isArray(init.headers)) {
        init.headers.push(['X-CSRFToken', token], ['X-CSRF-Token', token]);
      } else {
        init.headers['X-CSRFToken'] = token;
        init.headers['X-CSRF-Token'] = token;
      }
      // Toujours envoyer les cookies (session)
      if (init.credentials === undefined) {
        init.credentials = 'same-origin';
      }
    }
    return _fetch(input, init);
  };
});
