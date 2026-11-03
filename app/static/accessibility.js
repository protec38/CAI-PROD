/* Shared dialog focus management and progressive navigation enhancements. */
(function () {
  'use strict';
  let active = null, trigger = null;
  const previousInert = new Map();
  const focusable = node => [...node.querySelectorAll('a[href],button,input:not([type="hidden"]),select,textarea,[tabindex]')]
    .filter(item => !item.disabled && item.tabIndex >= 0 && item.getClientRects().length);
  function restore() {
    document.body.classList.remove('cai-dialog-open');
    for (const [node, value] of previousInert) node.inert = value;
    previousInert.clear();
    let destination = trigger;
    if (!destination?.isConnected && active) {
      const form = active.querySelector('form');
      const fiche = window.CAIDashboard?.getFiche(form?.dataset.ficheId);
      destination = fiche && document.getElementById('fiche-row-' + fiche.id)?.querySelector(`[data-cai-open-dialog="${active.id}"]`);
    }
    active = null; trigger = null;
    destination?.focus({preventScroll: true});
  }
  function openDialog(id) {
    const dialog = document.getElementById(id); if (!dialog) return;
    if (active === dialog) return;
    if (active) closeDialog(active.id);
    trigger = document.activeElement; active = dialog;
    for (const node of document.body.children) {
      if (node === dialog || node.contains(dialog) || node.tagName === 'SCRIPT' || node.tagName === 'LINK') continue;
      previousInert.set(node, node.inert); node.inert = true;
    }
    dialog.style.display = 'flex';
    document.body.classList.add('cai-dialog-open');
    const first = dialog.querySelector('textarea,input:not([type="hidden"]):not([readonly])');
    (first || focusable(dialog)[0] || dialog).focus({preventScroll: true});
  }
  function closeDialog(id) {
    const dialog = document.getElementById(id); if (!dialog) return;
    dialog.style.display = 'none';
    if (active === dialog) restore();
  }
  window.CAIUI = {openDialog, closeDialog};
  document.addEventListener('keydown', event => {
    if (active) {
      if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); closeDialog(active.id); return; }
      if (event.key === 'Tab') {
        const items = focusable(active), first = items[0], last = items.at(-1);
        if (!first) { event.preventDefault(); active.focus(); return; }
        if (event.shiftKey && (document.activeElement === first || document.activeElement === active)) {
          event.preventDefault(); last.focus();
        } else if (!event.shiftKey && (document.activeElement === last || !active.contains(document.activeElement))) {
          event.preventDefault(); first.focus();
        }
      }
    } else if (event.key === 'Escape') {
      document.querySelectorAll('.dashboard-menu[open],.cai-sync-details[open]').forEach(menu => {
        menu.open = false; menu.querySelector('summary')?.focus();
      });
    }
  }, true);
  document.addEventListener('click', event => {
    document.querySelectorAll('.dashboard-menu[open]').forEach(menu => { if (!menu.contains(event.target)) menu.open = false; });
  });
  function viewport() {
    const view = window.visualViewport;
    document.documentElement.style.setProperty('--cai-viewport-height', (view?.height || window.innerHeight) + 'px');
    document.documentElement.style.setProperty('--cai-viewport-top', (view?.offsetTop || 0) + 'px');
  }
  viewport();
  window.visualViewport?.addEventListener('resize', viewport);
  window.visualViewport?.addEventListener('scroll', viewport);
  window.addEventListener('resize', viewport);
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.modal[role="dialog"]').forEach(dialog => {
      new MutationObserver(() => { if (active === dialog && getComputedStyle(dialog).display === 'none') restore(); })
        .observe(dialog, {attributes: true, attributeFilter: ['style']});
    });
    document.querySelectorAll('label[for]').forEach(label => {
      if (document.getElementById(label.htmlFor)) return;
      const input = label.closest('form')?.elements.namedItem(label.htmlFor);
      if (input instanceof HTMLElement && !input.id) input.id = label.htmlFor;
    });
  });
})();
