(function () {
  'use strict';
  const defaults = {theme:'light',accent:'blue',font_size:'normal',layout_width:'standard',corners:'rounded'};
  const palettes = {blue:['#174f86','#a8d4ff'],teal:['#12655f','#91e0d6'],violet:['#6740a5','#d4b6ff'],orange:['#994400','#ffcb96']};
  const media = matchMedia('(prefers-color-scheme: dark)');
  let current = {};
  function apply(prefs = {}) {
    current = {...defaults,...prefs};
    const body = document.body;
    const dark = current.theme === 'dark' || current.theme === 'system' && media.matches;
    body.classList.add('cai-personal');
    body.dataset.theme = dark ? 'dark' : 'light';
    body.dataset.fontSize = current.font_size;
    body.dataset.width = current.layout_width;
    body.dataset.corners = current.corners;
    body.classList.toggle('cai-stripes',!!current.stripe_rows);
    body.classList.toggle('cai-reduce-motion',!!current.reduce_motion);
    const palette = palettes[current.accent] || palettes.blue;
    body.style.setProperty('--cai-accent',palette[0]);
    body.style.setProperty('--cai-link',dark ? palette[1] : palette[0]);
    body.style.setProperty('--cai-font-size',current.font_size === 'extra' ? '20px' : current.font_size === 'large' ? '18px' : '16px');
    for (const key of ['heure_arrivee','difficultes','competences','bagages']) body.classList.toggle('cai-hide-'+key,prefs[key]===false);
    body.classList.toggle('cai-compact',!!prefs.compact);
    body.classList.toggle('cai-hide-counters',prefs.show_counters===false);
  }
  media.addEventListener('change',()=>apply(current));
  document.addEventListener('DOMContentLoaded',()=>{
    const form=document.getElementById('appearance-settings');if(!form)return;
    const preview=()=>{
      const prefs={};for(const input of form.elements)if(input.name && !['csrf_token','next','lock_minutes'].includes(input.name))prefs[input.name]=input.type==='checkbox'?input.checked:input.value;
      apply(prefs);
    };
    form.addEventListener('change',preview);
    document.getElementById('reset-appearance')?.addEventListener('click',()=>{
      for(const input of form.elements){if(input.name in defaults)input.value=defaults[input.name];else if(input.type==='checkbox')input.checked=!['compact','stripe_rows','reduce_motion'].includes(input.name);}
      preview();
    });
  });
  window.CAIAppearance={apply};
})();
