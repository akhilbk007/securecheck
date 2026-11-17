// SecureCheck front end.
// Everything shown in the report comes from a third-party server (header
// values, cookie names, certificate fields), so it is untrusted input. This
// file never uses innerHTML: all text goes through textContent, and the page
// is served with a CSP that forbids inline script.
(function () {
  "use strict";

  var form = document.getElementById("scan-form");
  var input = document.getElementById("url");
  var button = document.getElementById("scan-button");
  var status = document.getElementById("status");
  var intro = document.getElementById("intro");
  var report = document.getElementById("report");
  var ledger = document.getElementById("ledger");
  var lastResult = null;
  var ticker = null;

  var STATUS_WORD = { pass: "Pass", warn: "Warn", fail: "Fail", info: "Note" };
  var GRADE_COLOR = { "A+": "--pass", A: "--pass", B: "--pass", C: "--warn", D: "--warn", F: "--fail" };
  var STEPS = [
    "Resolving the domain",
    "Negotiating TLS versions",
    "Reading the certificate",
    "Reading response headers",
    "Checking DNS records"
  ];

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function setStatus(text, isError) {
    status.textContent = text;
    status.className = isError ? "status error" : "status";
  }

  function startTicker() {
    var i = 0;
    setStatus(STEPS[0] + "…");
    ticker = setInterval(function () {
      i += 1;
      if (i < STEPS.length) {
        setStatus(STEPS[i] + "…");
      } else if (i > STEPS.length + 1) {
        // Free hosting puts the scanner to sleep when nobody is using it.
        setStatus("Waking up the scanner. The first scan after a quiet spell can take up to a minute…");
      }
    }, 1400);
  }

  function stopTicker() {
    clearInterval(ticker);
    ticker = null;
  }

  function scan(url) {
    button.disabled = true;
    button.textContent = "Scanning";
    startTicker();

    fetch("api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    })
      .then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (!res.ok) throw new Error(data.error || "The scan failed. Try again.");
          return data;
        });
      })
      .then(function (data) {
        stopTicker();
        lastResult = data;
        render(data);
        setStatus("Scanned " + data.host + " in " + (data.duration_ms / 1000).toFixed(1) + " seconds" +
          (data.cached ? " (result from the last five minutes)." : "."));
        history.replaceState(null, "", "?url=" + encodeURIComponent(data.host));
      })
      .catch(function (err) {
        stopTicker();
        setStatus(err.message || "The scan failed. Try again.", true);
      })
      .then(function () {
        button.disabled = false;
        button.textContent = "Scan site";
      });
  }

  function fact(list, label, value) {
    if (value === undefined || value === null || value === "") return;
    var row = el("div");
    row.appendChild(el("dt", null, label));
    row.appendChild(el("dd", null, value));
    list.appendChild(row);
  }

  function render(data) {
    intro.hidden = true;
    report.hidden = false;

    var stamp = document.getElementById("stamp");
    stamp.style.setProperty("--stamp", "var(" + (GRADE_COLOR[data.grade] || "--ink") + ")");
    stamp.setAttribute("aria-label", "Grade " + data.grade + ", score " + data.score + " out of 100");
    document.getElementById("grade").textContent = data.grade;
    document.getElementById("score").textContent = data.score + " / 100";
    stamp.classList.remove("land");
    void stamp.offsetWidth; // restart the animation
    stamp.classList.add("land");

    document.getElementById("report-host").textContent = data.host;
    document.getElementById("report-meta").textContent =
      "Scanned " + new Date(data.scanned_at).toLocaleString();

    var tally = document.getElementById("tally");
    tally.replaceChildren();
    [["fail", "to fix"], ["warn", "to improve"], ["pass", "passed"]].forEach(function (pair) {
      var n = data.counts[pair[0]] || 0;
      tally.appendChild(el("li", pair[0], n + " " + pair[1]));
    });

    var facts = document.getElementById("facts");
    facts.replaceChildren();
    var tls = data.tls || {};
    fact(facts, "Server address", data.ip);
    fact(facts, "Negotiated", tls.negotiated ? tls.negotiated.replace("v", " ") : "");
    if (tls.protocols) {
      var on = Object.keys(tls.protocols).filter(function (k) { return tls.protocols[k] === true; });
      fact(facts, "Versions accepted", on.join(", ").replace(/TLS /g, "") || "none");
    }
    if (tls.certificate) {
      fact(facts, "Certificate authority", tls.certificate.issuer);
      fact(facts, "Certificate expires", tls.certificate.expires + " (" + tls.certificate.days_left + " days)");
      fact(facts, "Certificate key", tls.certificate.key);
    }

    var note = document.getElementById("cert-note");
    if (tls.certificate && typeof tls.certificate.days_left === "number") {
      var days = tls.certificate.days_left;
      var when = tls.certificate.expires_text || tls.certificate.expires;
      note.textContent = days < 0
        ? "TLS certificate expired on " + when + "."
        : "TLS certificate expires on " + when + ", in " + days + (days === 1 ? " day." : " days.");
      note.className = "cert-note " + (days < 14 ? "fail" : days < 30 ? "warn" : "pass");
      note.hidden = false;
    } else {
      note.hidden = true;
    }

    ledger.replaceChildren();
    data.categories.forEach(function (category) {
      var items = data.findings.filter(function (f) { return f.category === category; });
      if (!items.length) return;
      ledger.appendChild(el("h3", null, category));
      var order = { fail: 0, warn: 1, info: 2, pass: 3 };
      items.sort(function (a, b) { return order[a.status] - order[b.status]; });
      items.forEach(function (f) { ledger.appendChild(renderFinding(f)); });
    });

    renderCompliance(data.compliance || []);

    report.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  var CONTROL_WORD = { fail: "Gap", warn: "Partial", pass: "No gap" };

  function renderCompliance(frameworks) {
    if (!frameworks.length) return;
    ledger.appendChild(el("h3", null, "Compliance mapping"));
    ledger.appendChild(el("p", "ledger-note",
      "How these findings relate to common frameworks. A web scan covers only part of each control, " +
      "so this shows where to look and is not an audit result."));
    frameworks.forEach(function (fw) {
      if (!fw.controls.length) return;
      var box = el("details", "framework");
      var summary = el("summary");
      summary.appendChild(el("span", "fw-name", fw.framework));
      var parts = [];
      if (fw.counts.fail) parts.push(fw.counts.fail + " with gaps");
      if (fw.counts.warn) parts.push(fw.counts.warn + " partial");
      if (fw.counts.pass) parts.push(fw.counts.pass + " with no gap found");
      summary.appendChild(el("span", "fw-counts", parts.join(", ")));
      box.appendChild(summary);
      fw.controls.forEach(function (c) {
        var row = el("div", "ctl-row");
        row.appendChild(el("span", "mark " + c.status, CONTROL_WORD[c.status] || c.status));
        var text = el("div");
        text.appendChild(el("p", "ctl-name", c.id + "  " + c.name));
        var gaps = c.checks.filter(function (k) { return k.status !== "pass"; })
          .map(function (k) { return k.title; });
        text.appendChild(el("p", "ctl-checks", gaps.length
          ? "Needs attention: " + gaps.join("; ")
          : c.checks.length + (c.checks.length === 1 ? " related check passed" : " related checks passed")));
        row.appendChild(text);
        box.appendChild(row);
      });
      ledger.appendChild(box);
    });
  }

  function controlsLine(controls) {
    var groups = {};
    var order = [];
    controls.forEach(function (c) {
      if (!groups[c.framework]) { groups[c.framework] = []; order.push(c.framework); }
      groups[c.framework].push(c.id);
    });
    var p = el("p", "controls");
    p.appendChild(el("span", "controls-label", "Related controls"));
    order.forEach(function (name) {
      p.appendChild(el("span", "ctl", name + ": " + groups[name].join(", ")));
    });
    return p;
  }

  function renderFinding(f) {
    var details = el("details", "finding " + f.status);
    if (f.status === "fail") details.open = true;

    var summary = el("summary");
    summary.appendChild(el("span", "mark " + f.status, STATUS_WORD[f.status] || f.status));
    summary.appendChild(el("span", "f-title", f.title));
    details.appendChild(summary);

    var body = el("div", "f-body");
    body.appendChild(el("p", null, f.detail));
    if (f.evidence) body.appendChild(el("code", null, f.evidence));
    if (f.fix && (f.status === "fail" || f.status === "warn")) {
      body.appendChild(el("p", "fix", "Fix: " + f.fix));
    }
    if (f.controls && f.controls.length) body.appendChild(controlsLine(f.controls));
    if (f.reference && /^https:\/\//.test(f.reference)) {
      var p = el("p");
      var a = el("a", null, "Read more");
      a.href = f.reference;
      a.rel = "noopener noreferrer";
      a.target = "_blank";
      p.appendChild(a);
      body.appendChild(p);
    }
    details.appendChild(body);
    return details;
  }

  // Hide the "https://" hint once the visitor types or pastes a scheme.
  var schemeHint = document.querySelector(".scheme");
  function syncScheme() { schemeHint.hidden = input.value.indexOf("://") !== -1; }
  input.addEventListener("input", syncScheme);

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var value = input.value.trim();
    if (!value) {
      setStatus("Enter a web address to scan, such as example.com.", true);
      input.focus();
      return;
    }
    scan(value);
  });

  document.getElementById("copy-link").addEventListener("click", function (event) {
    var btn = event.currentTarget;
    var done = function (text) {
      btn.textContent = text;
      setTimeout(function () { btn.textContent = "Copy link"; }, 1800);
    };
    if (navigator.clipboard) {
      navigator.clipboard.writeText(location.href).then(
        function () { done("Link copied"); },
        function () { done("Copy from address bar"); }
      );
    } else {
      done("Copy from address bar");
    }
  });

  document.getElementById("download-pdf").addEventListener("click", function (event) {
    if (!lastResult) return;
    var btn = event.currentTarget;
    var host = lastResult.host;
    btn.disabled = true;
    btn.textContent = "Preparing report";
    fetch("api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: host })
    })
      .then(function (res) {
        if (!res.ok) {
          return res.json().catch(function () { return {}; }).then(function (data) {
            throw new Error(data.error || "The report could not be created. Try again.");
          });
        }
        return res.blob();
      })
      .then(function (blob) {
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "securecheck-" + host + ".pdf";
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
      })
      .catch(function (err) { setStatus(err.message, true); })
      .then(function () {
        btn.disabled = false;
        btn.textContent = "Download report (PDF)";
      });
  });

  document.getElementById("download-json").addEventListener("click", function () {
    if (!lastResult) return;
    var blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "securecheck-" + lastResult.host + ".json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  });

  // Theme toggle. theme.js has already applied the saved or system theme.
  var themeToggle = document.getElementById("theme-toggle");
  function paintThemeToggle() {
    var dark = document.documentElement.getAttribute("data-theme") === "dark";
    themeToggle.textContent = dark ? "Light mode" : "Dark mode";
  }
  themeToggle.addEventListener("click", function () {
    var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("securecheck-theme", next); } catch (e) { /* storage unavailable */ }
    paintThemeToggle();
  });
  paintThemeToggle();

  // Shareable links: /?url=example.com runs the scan on load.
  var preset = new URLSearchParams(location.search).get("url");
  if (preset) {
    input.value = preset;
    syncScheme();
    scan(preset);
  }
})();
