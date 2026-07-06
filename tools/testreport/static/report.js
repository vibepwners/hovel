(function () {
  const state = {
    report: null,
    filtered: [],
    selected: null,
    tab: "log",
  };

  const app = document.getElementById("report-app");

  fetch("data/report.json")
    .then((response) => response.json())
    .then((report) => {
      state.report = report;
      state.filtered = report.targets;
      state.selected = report.targets[0] || null;
      render();
      window.addEventListener("hashchange", selectFromHash);
      selectFromHash();
    })
    .catch((error) => {
      app.innerHTML = `<p class="empty-state">Could not load report data: ${escapeHtml(String(error))}</p>`;
    });

  document.querySelectorAll("[data-commit]").forEach((button) => {
    button.addEventListener("click", () => copyCommit(button));
  });

  function render() {
    const report = state.report;
    app.innerHTML = `
      <section class="summary-grid">
        ${metric("Targets", report.totals.targets)}
        ${metric("Cases", report.totals.cases)}
        ${metric("Failed", report.totals.statuses.FAILED || 0)}
        ${metric("Passed", report.totals.statuses.PASSED || 0)}
        ${metric("Suites", Object.keys(report.totals.suites).length)}
        ${metric("Duration", `${Number(report.totals.duration || 0).toFixed(2)}s`)}
      </section>
      ${renderSuiteBreakdown(report)}
      <section class="report-controls">
        <div class="control">
          <label for="query">Search</label>
          <input id="query" type="search" placeholder="//sdk/rust or log text">
        </div>
        <div class="control">
          <label for="status">Status</label>
          <select id="status">${options(["all"].concat(Object.keys(report.totals.statuses)))}</select>
        </div>
        <div class="control">
          <label for="suite">Suite</label>
          <select id="suite">${options(["all"].concat(Object.keys(report.totals.suites)))}</select>
        </div>
        <div class="control">
          <label for="language">Language</label>
          <select id="language">${options(["all"].concat(Object.keys(report.totals.languages)))}</select>
        </div>
      </section>
      <section class="report-grid">
        <div class="target-list" id="target-list"></div>
        <article class="target-detail" id="target-detail"></article>
      </section>
    `;
    ["query", "status", "suite", "language"].forEach((id) => {
      document.getElementById(id).addEventListener("input", applyFilters);
    });
    renderTargets();
    renderDetail();
  }

  function metric(label, value) {
    return `<div class="metric"><span class="metric-label">${escapeHtml(label)}</span><span class="metric-value">${escapeHtml(String(value))}</span></div>`;
  }

  function renderSuiteBreakdown(report) {
    const breakdown = report.totals.suite_breakdown || {};
    const rows = Object.keys(breakdown).sort().map((suite) => {
      const item = breakdown[suite];
      const statuses = item.statuses || {};
      return `
        <tr>
          <td>${escapeHtml(suite)}</td>
          <td>${Number(item.targets || 0)}</td>
          <td>${Number(item.cases || 0)}</td>
          <td>${Number(statuses.FAILED || 0) + Number(statuses.ERROR || 0) + Number(statuses.TIMEOUT || 0)}</td>
          <td>${Number(statuses.PASSED || 0)}</td>
          <td>${Number(item.duration || 0).toFixed(2)}s</td>
        </tr>
      `;
    }).join("");
    if (!rows) {
      return "";
    }
    return `
      <section class="suite-breakdown">
        <div class="section-heading">
          <h2>Suites</h2>
        </div>
        <table>
          <thead><tr><th>Suite</th><th>Targets</th><th>Cases</th><th>Failing</th><th>Passed</th><th>Duration</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </section>
    `;
  }

  function options(values) {
    const uniqueValues = Array.from(new Set(values));
    const sortedValues = uniqueValues.filter((value) => value !== "all").sort();
    const orderedValues = uniqueValues.includes("all") ? ["all"].concat(sortedValues) : sortedValues;
    return orderedValues.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
  }

  function applyFilters() {
    const query = document.getElementById("query").value.toLowerCase();
    const status = document.getElementById("status").value;
    const suite = document.getElementById("suite").value;
    const language = document.getElementById("language").value;
    state.filtered = state.report.targets.filter((target) => {
      const matchesQuery = !query || [
        target.label,
        target.suite,
        target.language,
        target.status,
        target.raw_log_path,
        target.raw_xml_path,
      ].join(" ").toLowerCase().includes(query);
      return matchesQuery
        && (status === "all" || target.status === status)
        && (suite === "all" || target.suite === suite)
        && (language === "all" || target.language === language);
    });
    if (!state.filtered.includes(state.selected)) {
      state.selected = state.filtered[0] || null;
    }
    renderTargets();
    renderDetail();
  }

  function renderTargets() {
    const list = document.getElementById("target-list");
    if (!state.filtered.length) {
      list.innerHTML = `<p class="empty-state">No targets match the current filters.</p>`;
      return;
    }
    list.innerHTML = state.filtered.map((target) => `
      <button class="target-row" data-label="${escapeHtml(target.label)}" aria-selected="${target === state.selected}">
        ${statusBadge(target.status)}
        <span>
          <span class="target-label">${escapeHtml(target.label)}</span>
          <span class="target-sub">${escapeHtml(target.suite)} · ${escapeHtml(target.language)} · ${Number(target.duration || 0).toFixed(2)}s</span>
        </span>
        <span class="target-sub">${target.cases.length || 0} cases</span>
      </button>
    `).join("");
    list.querySelectorAll(".target-row").forEach((button) => {
      button.addEventListener("click", () => {
        const label = button.getAttribute("data-label");
        state.selected = state.report.targets.find((target) => target.label === label);
        window.location.hash = `target=${encodeURIComponent(label)}`;
        renderTargets();
        renderDetail();
      });
    });
  }

  function renderDetail() {
    const detail = document.getElementById("target-detail");
    const target = state.selected;
    if (!target) {
      detail.innerHTML = `<p class="empty-state">Select a target to inspect logs, XML, and case details.</p>`;
      return;
    }
    detail.innerHTML = `
      <div class="detail-heading">
        <h2>${escapeHtml(target.label)}</h2>
        ${statusBadge(target.status)}
      </div>
      <p class="detail-meta">${escapeHtml(target.suite)} · ${escapeHtml(target.language)} · attempt ${target.attempts} · run ${target.run} · shard ${target.shard}</p>
      <p><code>task test -- ${escapeHtml(target.label)}</code></p>
      <div class="tabs">
        ${tab("log", "Log")}
        ${tab("cases", `Cases (${target.cases.length})`)}
        ${tab("xml", "XML")}
        ${tab("outputs", `Outputs (${target.outputs.length})`)}
      </div>
      <div id="tab-body"></div>
    `;
    detail.querySelectorAll(".tab").forEach((button) => {
      button.addEventListener("click", () => {
        state.tab = button.getAttribute("data-tab");
        renderDetail();
      });
    });
    renderTabBody(target);
  }

  function tab(id, label) {
    return `<button class="tab" data-tab="${id}" aria-selected="${state.tab === id}">${escapeHtml(label)}</button>`;
  }

  function renderTabBody(target) {
    const body = document.getElementById("tab-body");
    if (state.tab === "cases") {
      body.innerHTML = renderCases(target);
    } else if (state.tab === "xml") {
      renderTextFile(body, target.xml_path, "No XML file was captured for this target.");
    } else if (state.tab === "outputs") {
      body.innerHTML = target.outputs.length
        ? `<ul>${target.outputs.map((item) => `<li><code>${escapeHtml(item)}</code></li>`).join("")}</ul>`
        : `<p class="empty-state">No undeclared outputs were captured.</p>`;
    } else {
      renderTextFile(body, target.log_path, "No log file was captured for this target.");
    }
  }

  function renderCases(target) {
    if (!target.cases.length) {
      return `<p class="empty-state">This target did not expose per-case XML. Use the Log tab for full output.</p>`;
    }
    return `<table class="case-table"><thead><tr><th>Status</th><th>Case</th><th>Class</th><th>Duration</th><th>Evidence</th></tr></thead><tbody>
      ${target.cases.map((testCase) => {
        const evidence = [testCase.message, testCase.output].filter(Boolean).join("\n\n");
        return `<tr><td>${statusBadge(testCase.status)}</td><td>${escapeHtml(testCase.name)}</td><td>${escapeHtml(testCase.classname || "")}</td><td>${Number(testCase.duration || 0).toFixed(3)}s</td><td class="case-evidence">${evidence ? `<pre>${escapeHtml(evidence)}</pre>` : ""}</td></tr>`;
      }).join("")}
    </tbody></table>`;
  }

  function renderTextFile(container, path, emptyMessage) {
    if (!path) {
      container.innerHTML = `<p class="empty-state">${escapeHtml(emptyMessage)}</p>`;
      return;
    }
    container.innerHTML = `<pre class="log-frame">Loading ${escapeHtml(path)}...</pre>`;
    fetch(path)
      .then((response) => response.ok ? response.text() : Promise.reject(new Error(response.statusText)))
      .then((text) => {
        container.innerHTML = `<pre class="log-frame">${escapeHtml(text)}</pre>`;
      })
      .catch((error) => {
        container.innerHTML = `<p class="empty-state">Could not load ${escapeHtml(path)}: ${escapeHtml(String(error))}</p>`;
      });
  }

  function selectFromHash() {
    const match = window.location.hash.match(/target=([^&]+)/);
    if (!match || !state.report) return;
    const label = decodeURIComponent(match[1]);
    const target = state.report.targets.find((item) => item.label === label);
    if (target) {
      state.selected = target;
      renderTargets();
      renderDetail();
    }
  }

  function statusBadge(status) {
    return `<span class="status status-${String(status).toLowerCase()}">${escapeHtml(status || "UNKNOWN")}</span>`;
  }

  function copyCommit(button) {
    const commit = button.getAttribute("data-commit") || "";
    const stateLabel = button.querySelector(".commit-copy-state");
    const markCopied = () => {
      if (!stateLabel) return;
      stateLabel.textContent = "copied";
      window.setTimeout(() => {
        stateLabel.textContent = "copy";
      }, 1400);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(commit).then(markCopied).catch(() => fallbackCopy(commit, markCopied));
      return;
    }
    fallbackCopy(commit, markCopied);
  }

  function fallbackCopy(value, onCopied) {
    const input = document.createElement("textarea");
    input.value = value;
    input.setAttribute("readonly", "");
    input.style.position = "fixed";
    input.style.opacity = "0";
    document.body.appendChild(input);
    input.select();
    try {
      document.execCommand("copy");
      onCopied();
    } finally {
      document.body.removeChild(input);
    }
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
})();
