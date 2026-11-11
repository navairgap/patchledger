/* PatchLedger website — minimal, dependency-free behavior. */

(function () {
  "use strict";

  var toggle = document.querySelector(".nav-toggle");
  var nav = document.querySelector(".site-nav");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    // Close the menu after navigating (mobile).
    nav.addEventListener("click", function (event) {
      if (event.target.tagName === "A") {
        nav.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  // Subtle scroll effect: lift sections into view without heavy animation.
  var sections = document.querySelectorAll(".section");
  if ("IntersectionObserver" in window) {
    var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!reduceMotion) {
      var observer = new IntersectionObserver(
        function (entries) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting) {
              entry.target.style.opacity = "1";
              entry.target.style.transform = "none";
              observer.unobserve(entry.target);
            }
          });
        },
        { threshold: 0.08 }
      );
      sections.forEach(function (section) {
        section.style.opacity = "0.9";
        section.style.transform = "translateY(6px)";
        section.style.transition = "opacity 320ms ease, transform 320ms ease";
        observer.observe(section);
      });
    }
  }
})();
