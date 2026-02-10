(function() {
  document.addEventListener('contextmenu', function(e) { e.preventDefault(); });
  document.addEventListener('dragstart', function(e) { e.preventDefault(); });
  document.addEventListener('selectstart', function(e) { e.preventDefault(); });
  document.addEventListener('copy', function(e) { e.preventDefault(); });
  document.addEventListener('cut', function(e) { e.preventDefault(); });

  document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && ['c','a','s','u','p'].indexOf(e.key.toLowerCase()) !== -1) {
      e.preventDefault();
    }
  });

  document.addEventListener('touchstart', function(e) {
    if (e.target.tagName === 'IMG') {
      e.target.style.pointerEvents = 'none';
      setTimeout(function() { e.target.style.pointerEvents = ''; }, 300);
    }
  }, { passive: false });

  document.querySelectorAll('img').forEach(function(img) {
    img.setAttribute('draggable', 'false');
    img.addEventListener('dragstart', function(e) { e.preventDefault(); });
  });

  var observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(m) {
      m.addedNodes.forEach(function(node) {
        if (node.tagName === 'IMG') {
          node.setAttribute('draggable', 'false');
          node.addEventListener('dragstart', function(e) { e.preventDefault(); });
        }
        if (node.querySelectorAll) {
          node.querySelectorAll('img').forEach(function(img) {
            img.setAttribute('draggable', 'false');
            img.addEventListener('dragstart', function(e) { e.preventDefault(); });
          });
        }
      });
    });
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();
