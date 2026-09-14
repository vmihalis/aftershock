const elements = {
  main: document.querySelector("#main"),
  errorBanner: document.querySelector("#error-banner"),
  errorMessage: document.querySelector("#error-message"),
  retryButton: document.querySelector("#retry-button"),
  modeFlag: document.querySelector("#mode-flag"),
  connection: document.querySelector("#connection"),
  connectionLabel: document.querySelector("#connection-label"),
  incidentId: document.querySelector("#incident-id"),
  severity: document.querySelector("#severity"),
  incidentTitle: document.querySelector("#incident-title"),
  repository: document.querySelector("#repository"),
  headSha: document.querySelector("#head-sha"),
  capsuleRevision: document.querySelector("#capsule-revision"),
  capsuleDigest: document.querySelector("#capsule-digest"),
  statePanel: document.querySelector("#state-panel"),
  assessmentState: document.querySelector("#assessment-state"),
  assessmentSummary: document.querySelector("#assessment-summary"),
  frameCount: document.querySelector("#frame-count"),
  frameDots: document.querySelector("#frame-dots"),
  matrixRows: document.querySelector("#matrix-rows"),
  runtime: document.querySelector("#runtime"),
  network: document.querySelector("#network"),
  credentials: document.querySelector("#credentials"),
  filesystem: document.querySelector("#filesystem"),
  timeline: document.querySelector("#timeline"),
  artifacts: document.querySelector("#artifacts"),
  resetButton: document.querySelector("#reset-button"),
  advanceButton: document.querySelector("#advance-button"),
  advanceLabel: document.querySelector("#advance-label"),
  announcer: document.querySelector("#announcer"),
};

const stateLabels = {
  POTENTIALLY_AFFECTED: "POTENTIALLY AFFECTED",
  OBSERVED_BY_CHECK: "OBSERVED BY CHECK",
  REMEDIATION_RETESTED: "REMEDIATION RETESTED",
  UNKNOWN: "UNKNOWN",
  EVIDENCE_STALE_FOR_CURRENT_HEAD: "EVIDENCE STALE FOR CURRENT HEAD",
};

const resultLabels = {
  pending: "Pending",
  effect_observed: "Effect observed",
  effect_absent: "Effect absent",
  inconclusive: "Inconclusive",
};

const artifactIcons = {
  source: "SRC",
  fixture: "FIX",
  receipt: "RCP",
  github_check: "CHK",
  github_issue: "ISS",
};

let currentView = null;
let busy = false;
let eventSource = null;

function setConnection(status, label) {
  elements.connection.classList.toggle("is-connected", status === "connected");
  elements.connection.classList.toggle("is-error", status === "error");
  elements.connectionLabel.textContent = label;
}

function setBusy(value) {
  busy = value;
  elements.resetButton.disabled = value;
  elements.advanceButton.disabled = value;
  elements.main.setAttribute("aria-busy", String(value));
}

function showError(error) {
  const message = error instanceof Error ? error.message : "Unknown connection error";
  elements.errorMessage.textContent = message;
  elements.errorBanner.hidden = false;
  setConnection("error", "API unavailable");
  document.body.classList.remove("is-loading");
}

function clearError() {
  elements.errorBanner.hidden = true;
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function renderFrameDots(frame, count) {
  const fragment = document.createDocumentFragment();
  for (let index = 1; index <= count; index += 1) {
    const dot = makeElement("span", "frame-dot");
    dot.classList.toggle("is-complete", index < frame);
    dot.classList.toggle("is-current", index === frame);
    fragment.append(dot);
  }
  elements.frameDots.replaceChildren(fragment);
}

function renderMatrix(rows) {
  const fragment = document.createDocumentFragment();
  rows.forEach((row, index) => {
    const line = makeElement("div", "matrix-row");
    line.setAttribute("role", "row");

    const name = makeElement("div", "matrix-name");
    name.setAttribute("role", "cell");
    name.append(makeElement("span", "matrix-index", String(index + 1).padStart(2, "0")));
    name.append(makeElement("span", "", row.label));

    const result = makeElement("div", "result-cell");
    result.setAttribute("role", "cell");
    result.append(makeElement("span", `result-status ${row.status}`, resultLabels[row.status] ?? row.status));
    result.append(makeElement("span", "result-effect", row.effect));

    const hash = makeElement("div", "hash-cell");
    hash.setAttribute("role", "cell");
    hash.append("before ", makeElement("strong", "", row.beforeHash));
    hash.append(document.createElement("br"));
    hash.append("after  ", makeElement("strong", "", row.afterHash));

    line.append(name, result, hash);
    fragment.append(line);
  });
  elements.matrixRows.replaceChildren(fragment);
}

function renderTimeline(events) {
  const fragment = document.createDocumentFragment();
  events.forEach((event) => {
    const item = makeElement("li", "timeline-item");
    const marker = makeElement("span", "timeline-marker");
    marker.setAttribute("aria-hidden", "true");
    const content = makeElement("div", "timeline-content");
    content.append(makeElement("h3", "", event.title));
    content.append(makeElement("p", "", event.detail));
    item.append(marker, content);
    fragment.append(item);
  });
  elements.timeline.replaceChildren(fragment);
  elements.timeline.scrollTop = elements.timeline.scrollHeight;
}

function renderArtifacts(artifacts) {
  const fragment = document.createDocumentFragment();
  artifacts.forEach((artifact) => {
    const link = makeElement("a", "artifact-link");
    link.href = artifact.url;
    link.target = "_blank";
    link.rel = "noreferrer";
    link.title = artifact.label;
    link.append(makeElement("span", "artifact-icon", artifactIcons[artifact.kind] ?? "ART"));
    link.append(makeElement("span", "", artifact.label));
    fragment.append(link);
  });
  elements.artifacts.replaceChildren(fragment);
}

function render(view, announce = false) {
  const previousState = currentView?.assessment.state;
  currentView = view;
  const state = view.assessment.state;

  document.body.dataset.state = state;
  document.body.classList.remove("is-loading");
  elements.modeFlag.textContent = view.meta.mode.replaceAll("-", " ").toUpperCase();
  elements.incidentId.textContent = view.incident.id;
  elements.incidentId.href = view.incident.sourceUrl;
  elements.severity.textContent = view.incident.severity;
  elements.incidentTitle.textContent = view.incident.title;
  elements.repository.textContent = `${view.repository.fullName} · ${view.repository.branch}`;
  elements.headSha.textContent = view.repository.headSha;
  elements.headSha.title = view.repository.headSha;
  elements.capsuleRevision.textContent = `${view.capsule.id}:${view.capsule.revision}`;
  elements.capsuleDigest.textContent = view.capsule.digest;
  elements.assessmentState.textContent = stateLabels[state] ?? state.replaceAll("_", " ");
  elements.assessmentSummary.textContent = view.assessment.summary;
  elements.frameCount.textContent = `Frame ${view.meta.frame} / ${view.meta.frameCount}`;
  elements.runtime.textContent = view.capabilities.runtime;
  elements.network.textContent = view.capabilities.network;
  elements.credentials.textContent = view.capabilities.credentials;
  elements.filesystem.textContent = view.capabilities.filesystem;
  elements.advanceLabel.textContent = view.meta.frame === view.meta.frameCount ? "Replay lifecycle" : "Advance evidence";

  renderFrameDots(view.meta.frame, view.meta.frameCount);
  renderMatrix(view.matrix);
  renderTimeline(view.events);
  renderArtifacts(view.artifacts);
  clearError();
  setConnection("connected", "Live replay connected");

  if (previousState && previousState !== state) {
    elements.statePanel.classList.remove("is-changing");
    requestAnimationFrame(() => elements.statePanel.classList.add("is-changing"));
  }
  if (announce) {
    elements.announcer.textContent = `Frame ${view.meta.frame}. ${stateLabels[state] ?? state}. ${view.assessment.summary}`;
  }
  document.title = `Aftershock · ${stateLabels[state] ?? state}`;
}

async function requestView(path, options) {
  const response = await fetch(path, {
    ...options,
    headers: { accept: "application/json", ...(options?.headers ?? {}) },
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

async function loadInitial() {
  setBusy(true);
  try {
    render(await requestView("/api/view"));
    connectEvents();
  } catch (error) {
    showError(error);
  } finally {
    setBusy(false);
  }
}

async function mutate(path) {
  if (busy) return;
  setBusy(true);
  try {
    const view = await requestView(path, { method: "POST" });
    render(view, true);
  } catch (error) {
    showError(error);
  } finally {
    setBusy(false);
  }
}

function connectEvents() {
  eventSource?.close();
  eventSource = new EventSource("/api/events");
  eventSource.addEventListener("open", () => setConnection("connected", "Live replay connected"));
  eventSource.addEventListener("view", (event) => {
    try {
      render(JSON.parse(event.data));
    } catch (error) {
      showError(error);
    }
  });
  eventSource.addEventListener("error", () => setConnection("error", "Replay reconnecting"));
}

elements.retryButton.addEventListener("click", loadInitial);
elements.resetButton.addEventListener("click", () => mutate("/api/demo/reset"));
elements.advanceButton.addEventListener("click", () => {
  const finalFrame = currentView && currentView.meta.frame === currentView.meta.frameCount;
  mutate(finalFrame ? "/api/demo/reset" : "/api/demo/advance");
});

document.addEventListener("keydown", (event) => {
  const target = event.target;
  if (target instanceof HTMLElement && target.closest("button, a, input, textarea, select")) return;
  if (event.key === "ArrowRight" || event.key === " ") {
    event.preventDefault();
    elements.advanceButton.click();
  }
  if (event.key.toLowerCase() === "r") {
    event.preventDefault();
    elements.resetButton.click();
  }
});

window.addEventListener("beforeunload", () => eventSource?.close());
loadInitial();
