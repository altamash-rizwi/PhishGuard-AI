"use strict";

document.addEventListener("click", function (event) {
  const button = event.target.closest("button");
  if (!button) return;

  if (button.hasAttribute("data-fill-url")) {
    const input = document.getElementById("url");
    if (!input) return;
    input.value = button.dataset.fillUrl || "";
    input.focus();
    return;
  }

  if (button.matches(".example-chip[data-url]")) {
    const input = document.getElementById("console-url");
    const form = button.closest(".console-hero-copy")?.querySelector(".console-scan-form");
    const exampleUrl = button.dataset.url;
    if (!input || !form || !exampleUrl) return;

    input.value = exampleUrl;
    input.setCustomValidity("");
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.focus();
    if (typeof form.requestSubmit === "function") {
      form.requestSubmit();
    } else {
      form.submit();
    }
    return;
  }

  if (button.hasAttribute("data-print-report")) {
    window.print();
  }
});
