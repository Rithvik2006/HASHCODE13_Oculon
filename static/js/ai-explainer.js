(function () {
  if (window.AI_EXPLAINER_LOADED) return;
  window.AI_EXPLAINER_LOADED = true;

  const API_BASE = window.AI_EXPLAINER_API || "/api";

  function createButton() {
    const btn = document.createElement("button");
    btn.className = "ai-explainer-btn";
    btn.innerText = "AI Explainer";
    btn.style.display = "none";
    document.body.appendChild(btn);
    return btn;
  }

  function createModal() {
    const modal = document.createElement("div");
    modal.className = "ai-explainer-modal hidden";
    modal.innerHTML = `
      <div class="ai-explainer-modal-content">
        <button class="ai-close">×</button>
        <div class="ai-modal-body">
          <h3 class="ai-title">AI Explainer</h3>
          <div class="ai-loading">Loading…</div>
          <pre class="ai-output"></pre>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
    return modal;
  }

  const button = createButton();
  const modal = createModal();

  let currentTarget = null;

  function showButtonAt(el) {
    const rect = el.getBoundingClientRect();
    button.style.left = (window.scrollX + rect.right - 110) + "px";
    button.style.top = (window.scrollY + rect.top + 10) + "px";
    button.style.display = "block";
  }

  function hideButton() {
    button.style.display = "none";
  }

  function openModal() {
    modal.classList.remove("hidden");
  }
  function closeModal() {
    modal.classList.add("hidden");
  }

  document.addEventListener("click", function (ev) {
    const t = ev.target;
    if (t.matches(".ai-explainer-btn")) {
      if (!currentTarget) return;
      // gather data attributes
      const graphType = currentTarget.dataset.graphType;
      const measurement = currentTarget.dataset.measurement;
      const field = currentTarget.dataset.field;
      const tagsJson = currentTarget.dataset.tags;
      let tags = undefined;
      try { tags = tagsJson ? JSON.parse(tagsJson) : undefined; } catch(e) {}
      showExplanation({ graph_type: graphType, measurement, field, tags });
    } else if (t.matches(".ai-close")) {
      closeModal();
    }
  });

  async function showExplanation(payload) {
    openModal();
    const output = modal.querySelector(".ai-output");
    const loading = modal.querySelector(".ai-loading");
    output.textContent = "";
    loading.style.display = "block";
    try {
      const r = await fetch(API_BASE + "/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const j = await r.json();
      loading.style.display = "none";
      if (r.ok) {
        try {
          const expl = j.explanation;
          output.textContent = JSON.stringify(expl, null, 2);
        } catch (e) {
          output.textContent = String(j.explanation || j.raw || JSON.stringify(j, null, 2));
        }
      } else {
        output.textContent = "Error: " + (j.detail || JSON.stringify(j));
      }
    } catch (e) {
      loading.style.display = "none";
      output.textContent = "Network or server error: " + e.toString();
    }
  }

  // Attach to elements
  function init() {
    const els = Array.from(document.querySelectorAll(".ai-graph[data-graph-type]"));
    els.forEach(el => {
      el.addEventListener("mouseenter", () => {
        currentTarget = el;
        showButtonAt(el);
      });
      el.addEventListener("mouseleave", () => {
        // hide after a short delay to allow clicking
        setTimeout(() => {
          if (!modal.classList.contains("hidden")) return;
          hideButton();
          currentTarget = null;
        }, 250);
      });
      // keyboard accessibility
      el.tabIndex = el.tabIndex || 0;
      el.addEventListener("focus", () => {
        currentTarget = el;
        showButtonAt(el);
      });
      el.addEventListener("blur", () => {
        hideButton();
        currentTarget = null;
      });
    });
  }

  window.addEventListener("load", init);
  // also run after SPA navigation (you can call window.AI_EXPLAINER_init() manually)
  window.AI_EXPLAINER_init = init;
})();
