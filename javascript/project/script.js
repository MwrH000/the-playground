const observer = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      entry.target.classList.add("visible");
    }
  });
}, { threshold: 0.2, rootMargin: "0px 0px -10% 0px" });

document.querySelectorAll(".reveal").forEach((group) => {
  Array.from(group.children).forEach((child, index) => {
    child.style.transitionDelay = `${index * 90}ms`;
  });
  observer.observe(group);
});

window.addEventListener("load", () => {
  document.body.classList.add("loaded");
});
