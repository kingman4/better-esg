// FDA ESG NextGen — Minimal app JS

// Auto-dismiss flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('[data-flash]').forEach(function(el) {
    setTimeout(function() {
      el.style.transition = 'opacity 0.3s ease';
      el.style.opacity = '0';
      setTimeout(function() { el.remove(); }, 300);
    }, 5000);
  });
});
