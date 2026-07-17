(function () {
  const state = {
    report: null,
    filtered: [],
    selected: null,
    detailTab: "log",
    view: "overview",
  };

  const reportViews = ["overview", "coverage", "suites", "jobs", "targets"];

  const app = document.getElementById("report-app");

  fetch("data/report.json")
    .then((response) => response.json())
    .then((report) => {
      state.report = report;
      state.filtered = report.targets;
      state.selected = report.targets[0] || null;
      renderMetadata(report);
      render();
      window.addEventListener("hashchange", selectFromHash);
      selectFromHash();
    })
    .catch(() => {
      app.innerHTML = `<p class="empty-state">No generated test evidence is attached to this site build. Run <code>task docs:report</code> to create it.</p>`;
    });

  function renderMetadata(report) {
    const metadata = document.getElementById("report-meta");
    const commit = String(report.commit || "").trim();
    const commitControl = commit
      ? ` · commit <button class="commit-copy" type="button" title="${escapeHtml(commit)}" data-commit="${escapeHtml(commit)}"><code>${escapeHtml(commit.slice(0, 12))}</code><span class="commit-copy-state">copy</span></button>`
      : "";
    metadata.innerHTML = `Generated <code>${escapeHtml(report.generated_at)}</code> · workflow <code>${escapeHtml(report.workflow)}</code> · job <code>${escapeHtml(report.job)}</code>${commitControl}`;
    metadata.querySelectorAll("[data-commit]").forEach((button) => {
      button.addEventListener("click", () => copyCommit(button));
    });
  }

  function render() {
    const report = state.report;
    const coverageCount = (report.coverage || []).length;
    const suiteCount = Object.keys(report.totals.suites || {}).length;
    const jobCount = (report.jobs || []).length;
    app.innerHTML = `
      <nav class="report-view-tabs" role="tablist" aria-label="Test report sections">
        ${viewTab("overview", "Overview")}
        ${viewTab("coverage", "Coverage", coverageCount)}
        ${viewTab("suites", "Suites", suiteCount)}
        ${viewTab("jobs", "Jobs", jobCount)}
        ${viewTab("targets", "Targets", report.totals.targets)}
      </nav>
      <section class="report-panel overview-panel" id="report-panel-overview" role="tabpanel" aria-labelledby="report-tab-overview" data-report-panel="overview">
        <div class="panel-intro">
          <div>
            <span class="panel-kicker">Latest evidence</span>
            <h2>Run at a glance</h2>
            <p>Repository-wide results from the attached report-producing workflow.</p>
          </div>
          ${runHealth(report)}
        </div>
        <section class="summary-grid" aria-label="Test summary">
          ${metric("Targets", report.totals.targets)}
          ${metric("Cases", report.totals.cases)}
          ${metric("Failed", report.totals.statuses.FAILED || 0)}
          ${metric("Passed", report.totals.statuses.PASSED || 0)}
          ${metric("Suites", suiteCount)}
          ${metric("Duration", `${Number(report.totals.duration || 0).toFixed(2)}s`)}
        </section>
      </section>
      <section class="report-panel" id="report-panel-coverage" role="tabpanel" aria-labelledby="report-tab-coverage" data-report-panel="coverage" hidden>
        ${renderCoverage(report)}
      </section>
      <section class="report-panel" id="report-panel-suites" role="tabpanel" aria-labelledby="report-tab-suites" data-report-panel="suites" hidden>
        ${renderSuiteBreakdown(report)}
      </section>
      <section class="report-panel" id="report-panel-jobs" role="tabpanel" aria-labelledby="report-tab-jobs" data-report-panel="jobs" hidden>
        ${renderJobs(report)}
      </section>
      <section class="report-panel targets-panel" id="report-panel-targets" role="tabpanel" aria-labelledby="report-tab-targets" data-report-panel="targets" hidden>
        <div class="section-heading target-section-heading">
          <div>
            <span class="panel-kicker">Bazel evidence</span>
            <h2>Test targets</h2>
            <p>Filter targets, then inspect their complete log, cases, XML, and outputs.</p>
          </div>
          <span class="result-count">${Number(report.totals.targets || 0)} targets</span>
        </div>
        <section class="target-workspace">
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
        </section>
      </section>
    `;
    bindViewTabs();
    ["query", "status", "suite", "language"].forEach((id) => {
      document.getElementById(id).addEventListener("input", applyFilters);
    });
    renderTargets();
    renderDetail();
    hydrateJobLogs();
    activateView(state.view);
  }

  function viewTab(id, label, count) {
    const badge = count === undefined ? "" : `<span class="report-tab-count">${escapeHtml(String(count))}</span>`;
    return `<button class="report-view-tab" id="report-tab-${id}" type="button" role="tab" aria-controls="report-panel-${id}" aria-selected="${state.view === id}" data-report-view="${id}"><span>${escapeHtml(label)}</span>${badge}</button>`;
  }

  function bindViewTabs() {
    const tabs = Array.from(document.querySelectorAll("[data-report-view]"));
    tabs.forEach((button, index) => {
      button.addEventListener("click", () => {
        activateView(button.getAttribute("data-report-view"));
        updateHash({ view: state.view });
      });
      button.addEventListener("keydown", (event) => {
        let next = index;
        if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
        else if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
        else if (event.key === "Home") next = 0;
        else if (event.key === "End") next = tabs.length - 1;
        else return;
        event.preventDefault();
        tabs[next].focus();
        tabs[next].click();
      });
    });
  }

  function activateView(view) {
    state.view = reportViews.includes(view) ? view : "overview";
    document.querySelectorAll("[data-report-view]").forEach((button) => {
      const selected = button.getAttribute("data-report-view") === state.view;
      button.setAttribute("aria-selected", String(selected));
      button.setAttribute("tabindex", selected ? "0" : "-1");
    });
    document.querySelectorAll("[data-report-panel]").forEach((panel) => {
      panel.hidden = panel.getAttribute("data-report-panel") !== state.view;
    });
  }

  function runHealth(report) {
    const statuses = report.totals.statuses || {};
    const failing = Number(statuses.FAILED || 0) + Number(statuses.ERROR || 0) + Number(statuses.TIMEOUT || 0);
    const flaky = Number(statuses.FLAKY || 0);
    const status = failing ? "FAILED" : flaky ? "FLAKY" : "PASSED";
    const label = failing ? `${failing} failing targets` : flaky ? `${flaky} flaky targets` : "All reported targets are healthy";
    return `<div class="run-health run-health-${status.toLowerCase()}">${statusBadge(status)}<span>${label}</span></div>`;
  }

  function metric(label, value) {
    return `<div class="metric"><span class="metric-label">${escapeHtml(label)}</span><span class="metric-value">${escapeHtml(String(value))}</span></div>`;
  }

  function renderCoverage(report) {
    const coverage = report.coverage || [];
    if (!coverage.length) {
      return `<p class="empty-state">No coverage evidence was attached to this report.</p>`;
    }
    return `
      <section class="coverage-section">
        <div class="section-heading">
          <div>
            <span class="panel-kicker">Quality thresholds</span>
            <h2>Test coverage</h2>
            <p>Ratchet-backed line metrics and the real-payload Squatter feature matrix.</p>
          </div>
          <span class="result-count">${coverage.length} metrics</span>
        </div>
        <div class="coverage-grid">
          ${coverage.map((item) => {
            const percentage = Math.max(0, Math.min(100, Number(item.percentage || 0)));
            const source = item.source_path
              ? `<a href="${escapeHtml(item.source_path)}">source evidence</a>`
              : `<span>source unavailable</span>`;
            return `
              <article class="coverage-card">
                <div class="coverage-heading">
                  <span class="coverage-scope">${escapeHtml(item.scope)}</span>
                  ${statusBadge(item.status)}
                </div>
                <h3>${escapeHtml(item.name)}</h3>
                <strong>${percentage.toFixed(2)}%</strong>
                <div class="coverage-track" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percentage}">
                  <span style="width: ${percentage}%"></span>
                </div>
                <p>${Number(item.covered || 0)} / ${Number(item.total || 0)} covered · minimum ${Number(item.minimum || 0).toFixed(2)}% · ${source}</p>
              </article>
            `;
          }).join("")}
        </div>
      </section>
    `;
  }

  function renderJobs(report) {
    const jobs = report.jobs || [];
    if (!jobs.length) {
      return "";
    }
    return `
      <section class="jobs-section">
        <div class="section-heading">
          <div>
            <span class="panel-kicker">Workflow evidence</span>
            <h2>Execution jobs</h2>
            <p>End-to-end workflow evidence with complete console logs for review.</p>
          </div>
          <span class="result-count">${jobs.length} ${jobs.length === 1 ? "job" : "jobs"}</span>
        </div>
        <div class="job-list">
          ${jobs.map((job) => `
            <details class="job-card" ${job.category === "e2e" ? "open" : ""}>
              <summary>
                <span>${statusBadge(job.status)} <strong>${escapeHtml(job.name)}</strong></span>
                <span class="job-meta">${escapeHtml(job.category)} · ${Number(job.duration || 0).toFixed(2)}s</span>
              </summary>
              ${job.description ? `<p>${escapeHtml(job.description)}</p>` : ""}
              ${job.log_path
                ? `<div class="job-log-heading"><span>Reviewer-oriented evidence</span><a href="${escapeHtml(job.log_path)}" target="_blank" rel="noopener">open complete log</a></div><div class="job-log" data-job-log="${escapeHtml(job.log_path)}"><p class="empty-state">Loading ${escapeHtml(job.log_path)}...</p></div>`
                : `<p class="empty-state">No complete log was captured for this job.</p>`}
            </details>
          `).join("")}
        </div>
      </section>
    `;
  }

  function hydrateJobLogs() {
    document.querySelectorAll("[data-job-log]").forEach((container) => {
      const path = container.getAttribute("data-job-log");
      fetch(path)
        .then((response) => response.ok ? response.text() : Promise.reject(new Error(response.statusText)))
        .then((contents) => {
          renderJobLog(container, contents);
        })
        .catch((error) => {
          container.innerHTML = `<p class="empty-state">Could not load ${escapeHtml(path)}: ${escapeHtml(String(error))}</p>`;
        });
    });
  }

  function renderJobLog(container, contents) {
    const marker = "\nRAW TRANSCRIPT APPENDICES\n";
    const boundary = contents.indexOf(marker);
    if (boundary < 0) {
      container.innerHTML = `<pre class="log-frame job-review-summary">${escapeHtml(contents)}</pre>`;
      return;
    }
    const summary = contents.slice(0, boundary).trimEnd();
    const transcripts = contents.slice(boundary + 1).trimEnd();
    const transcriptLines = transcripts ? transcripts.split("\n").length : 0;
    container.innerHTML = `
      <pre class="log-frame job-review-summary">${escapeHtml(summary)}</pre>
      <details class="job-raw-transcripts">
        <summary><span>Raw transcript appendices</span><span>${transcriptLines} lines · expand for command-level output</span></summary>
        <pre class="log-frame job-raw-log">${escapeHtml(transcripts)}</pre>
      </details>
    `;
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
          <div>
            <span class="panel-kicker">Repository slices</span>
            <h2>Suites</h2>
            <p>Bazel target and case totals grouped by repository slice.</p>
          </div>
          <span class="result-count">${Object.keys(breakdown).length} suites</span>
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
        activateView("targets");
        updateHash({ view: "targets", target: label });
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
      <div class="tabs" role="tablist" aria-label="Target evidence">
        ${detailTab("log", "Log")}
        ${detailTab("cases", `Cases (${target.cases.length})`)}
        ${detailTab("xml", "XML")}
        ${detailTab("outputs", `Outputs (${target.outputs.length})`)}
      </div>
      <div id="tab-body" role="tabpanel"></div>
    `;
    detail.querySelectorAll(".tab").forEach((button) => {
      button.addEventListener("click", () => {
        state.detailTab = button.getAttribute("data-tab");
        renderDetail();
      });
    });
    renderTabBody(target);
  }

  function detailTab(id, label) {
    return `<button class="tab" type="button" role="tab" data-tab="${id}" aria-selected="${state.detailTab === id}">${escapeHtml(label)}</button>`;
  }

  function renderTabBody(target) {
    const body = document.getElementById("tab-body");
    if (state.detailTab === "cases") {
      body.innerHTML = renderCases(target);
    } else if (state.detailTab === "xml") {
      renderTextFile(body, target.xml_path, "No XML file was captured for this target.");
    } else if (state.detailTab === "outputs") {
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
    if (!state.report) return;
    const parameters = hashParameters();
    const label = parameters.get("target");
    const target = label ? state.report.targets.find((item) => item.label === label) : null;
    if (target) {
      state.selected = target;
      renderTargets();
      renderDetail();
    }
    const requestedView = parameters.get("view");
    activateView(reportViews.includes(requestedView) ? requestedView : target ? "targets" : "overview");
  }

  function hashParameters() {
    return new URLSearchParams(window.location.hash.replace(/^#/, ""));
  }

  function updateHash(values) {
    const parameters = hashParameters();
    Object.entries(values).forEach(([key, value]) => {
      if (value) parameters.set(key, value);
      else parameters.delete(key);
    });
    const hash = parameters.toString();
    window.history.replaceState(null, "", hash ? `#${hash}` : window.location.pathname + window.location.search);
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
