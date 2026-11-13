const list = document.querySelector("#email-list");
const notice = document.querySelector("#notice");
const scanMorePanel = document.querySelector("#scan-more-panel");
const scanMoreButton = document.querySelector("#scan-more-button");
const composeDialog = document.querySelector("#compose-dialog");
const emailForm = document.querySelector("#email-form");
const formError = document.querySelector("#form-error");
const submitButton = document.querySelector("#submit-button");

let activeStatus = "all";
let allEmails = [];
let syncPollers = {};
let gmailAccount = null;
let gmailSync = null;

const statusLabels = {};

function updateStatusLabels() {
  for (const status of ["all", "inbox", "review", "quarantine"]) {
    statusLabels[status] = window.translate(status);
  }
}

function translateReason(reason) {
  const keywords = "Suspicious keywords detected: ";
  if (reason.startsWith(keywords)) {
    const match = reason.slice(keywords.length).match(/^(.*?) \((.*?)\)\.?$/);
    if (match) {
      return window.translate("reason.keywords", {
        terms: match[1],
        language: match[2]
      });
    }
  }
  const density = reason.match(
    /^Keyword density increased the score by (\d+) points\.$/
  );
  if (density) {
    return window.translate("reason.density", { points: density[1] });
  }
  const combination = reason.match(
    /^Multiple high-risk keywords with supporting signals increased the score by (\d+) points\.$/
  );
  if (combination) {
    return window.translate("reason.combination", { points: combination[1] });
  }
  const staticReasons = {
    "Email contains a link.": "reason.link",
    "URL contains an @ symbol.": "reason.urlAt",
    "URL is not using HTTPS.": "reason.noHttps",
    "Sender address appears invalid.": "reason.invalidSender"
  };
  if (staticReasons[reason]) return window.translate(staticReasons[reason]);

  const path = reason.match(
    /^URL path contains a suspicious sign-in or account route: (.*?)\.$/
  );
  if (path) return window.translate("reason.urlPath", { terms: path[1] });
  const file = reason.match(/^Suspicious file type detected: (.*?)$/);
  if (file) return window.translate("reason.fileType", { extension: file[1] });
  const brand = reason.match(/^Email may be impersonating (.*?)\.$/);
  if (brand) return window.translate("reason.brand", { brand: brand[1] });
  return reason;
}

function setNotice(message, isError = false) {
  notice.textContent = message;
  notice.classList.toggle("error", isError);
  notice.hidden = !message;
}

async function apiRequest(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (["POST", "PUT", "PATCH", "DELETE"].includes((options.method || "GET").toUpperCase())) {
    headers.set(
      "X-CSRF-Token",
      document.querySelector('meta[name="csrf-token"]')?.content || ""
    );
  }
  const response = await fetch(url, { ...options, headers });
  const contentType = response.headers.get("content-type") || "";
  const result = contentType.includes("application/json")
    ? await response.json()
    : null;

  if (!response.ok) {
    const error = new Error(result?.error || `Request failed (${response.status})`);
    error.code = result?.code;
    throw error;
  }
  return result;
}

function createElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function setCounts(emails) {
  const counts = {
    all: emails.length,
    inbox: emails.filter((email) => email.status === "inbox").length,
    review: emails.filter((email) => email.status === "review").length,
    quarantine: emails.filter((email) => email.status === "quarantine").length
  };

  for (const [status, count] of Object.entries(counts)) {
    document.querySelector(`#count-${status}`).textContent = count;
    if (status !== "all") {
      document.querySelector(`#stat-${status}`).textContent = count;
    }
  }
  document.querySelector("#stat-total").textContent = emails.length;
}

function formatDate(value) {
  if (!value) return window.translate("date.unavailable");
  const date = new Date(`${value.replace(" ", "T")}Z`);
  if (Number.isNaN(date.getTime())) return value;
  try {
    return new Intl.DateTimeFormat(`${document.documentElement.lang}-ZA`, {
        dateStyle: "medium",
        timeStyle: "short"
    }).format(date);
  } catch {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short"
    }).format(date);
  }
}

function statusBadge(status) {
  const label = statusLabels[status] || status;
  return createElement("span", `status-badge ${status}`, label);
}

function makeDetails(email) {
  const details = createElement("div", "email-details");
  details.hidden = true;

  const fields = [
    [window.translate("email.bodyLabel"), email.body || window.translate("email.noBody")],
    [window.translate("email.reasons"), null]
  ];

  for (const [label, value] of fields) {
    details.append(createElement("div", "detail-label", label));
    if (value !== null) {
      details.append(createElement("p", "detail-text", value));
      continue;
    }

    const reasons = createElement("div", "reason-list");
    const reasonList = Array.isArray(email.reasons)
      ? email.reasons
      : (email.reasons || "").split(";").map((reason) => reason.trim()).filter(Boolean);
    if (!reasonList.length) {
      reasons.append(createElement("span", "reason-chip", window.translate("email.noWarnings")));
    } else {
      for (const reason of reasonList) {
        reasons.append(createElement("span", "reason-chip", translateReason(reason)));
      }
    }
    details.append(reasons);
  }
  return details;
}

function makeEmailRow(email) {
  const row = createElement("article", "email-row");
  const main = createElement("div", "email-main");

  const senderBlock = createElement("div", "sender-block");
  senderBlock.append(createElement("div", "sender", email.sender || window.translate("email.unknownSender")));
  senderBlock.append(createElement("div", "date", formatDate(email.created_at)));

  const subjectBlock = createElement("div", "subject-block");
  subjectBlock.append(createElement("div", "subject", email.subject || window.translate("email.noSubject")));
  subjectBlock.append(createElement("div", "preview", (email.body || "").replace(/\s+/g, " ").trim() || window.translate("email.noBody")));

  const score = Number(email.risk_score) || 0;
  const riskBlock = createElement("div", "risk-block");
  const riskMeta = createElement("div", "risk-meta");
  riskMeta.append(createElement("span", "", window.translate("risk.score")));
  riskMeta.append(createElement("span", "risk-score", `${score}/100`));
  const track = createElement("div", "risk-track");
  const fill = createElement("div", `risk-fill ${score >= 70 ? "high" : score >= 30 ? "medium" : ""}`);
  fill.style.width = `${Math.min(100, Math.max(0, score))}%`;
  track.append(fill);
  riskBlock.append(riskMeta, track);

  const actions = createElement("div", "row-actions");
  actions.append(statusBadge(email.status));
  const menu = createElement("button", "row-menu", "•••");
  menu.type = "button";
  menu.title = window.translate("details.show");
  menu.setAttribute("aria-label", window.translate("details.show"));
  menu.setAttribute("aria-expanded", "false");
  actions.append(menu);

  main.append(senderBlock, subjectBlock, riskBlock, actions);
  const details = makeDetails(email);
  menu.addEventListener("click", () => {
    details.hidden = !details.hidden;
    menu.setAttribute("aria-expanded", String(!details.hidden));
    menu.title = window.translate(details.hidden ? "details.show" : "details.hide");
    menu.setAttribute("aria-label", menu.title);
  });
  row.append(main, details);

  const controls = createElement("div", "row-controls");
  const statusSelect = document.createElement("select");
  statusSelect.className = "status-select";
  statusSelect.setAttribute("aria-label", `${window.translate("moveTo")} ${email.sender}`);
  for (const status of ["inbox", "review", "quarantine"]) {
    const option = document.createElement("option");
    option.value = status;
    option.textContent = `${window.translate("moveTo")} ${statusLabels[status]}`;
    statusSelect.append(option);
  }
  statusSelect.value = email.status;
  statusSelect.addEventListener("change", async () => {
    try {
      await apiRequest(`/emails/${email.id}/move`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: statusSelect.value })
      });
      setNotice(window.translate("notice.updated"));
      await loadEmails();
    } catch (error) {
      setNotice(error.message, true);
      statusSelect.value = email.status;
    }
  });
  const deleteButton = createElement("button", "delete-button", window.translate("delete"));
  deleteButton.type = "button";
  deleteButton.addEventListener("click", async () => {
    if (!window.confirm(window.translate("delete.confirm", { sender: email.sender }))) return;
    try {
      await apiRequest(`/emails/${email.id}`, { method: "DELETE" });
      setNotice(window.translate("notice.deleted"));
      await loadEmails();
    } catch (error) {
      setNotice(error.message, true);
    }
  });
  controls.append(statusSelect, deleteButton);
  row.append(controls);
  return row;
}

function renderEmails(emails) {
  const visibleEmails = activeStatus === "all"
    ? emails
    : emails.filter((email) => email.status === activeStatus);
  list.replaceChildren();

  document.querySelector("#page-title").textContent = statusLabels[activeStatus];
  document.querySelector("#list-heading").textContent = statusLabels[activeStatus];
  document.querySelector("#list-description").textContent = activeStatus === "all"
    ? window.translate("list.allDescription")
    : activeStatus === "review"
      ? window.translate("list.reviewCount", { count: visibleEmails.length })
      : window.translate("list.statusCount", {
        count: visibleEmails.length,
        status: statusLabels[activeStatus]
      });

  if (!visibleEmails.length) {
    const empty = createElement("div", "empty-state");
    empty.append(createElement("div", "empty-icon", "✦"));
    empty.append(createElement(
      "strong",
      "",
      activeStatus === "all"
        ? window.translate("empty.noEmails")
        : window.translate("empty.noFolder", { status: statusLabels[activeStatus] })
    ));
    empty.append(createElement("p", "", window.translate("empty.prompt")));
    list.append(empty);
    return;
  }
  for (const email of visibleEmails) list.append(makeEmailRow(email));
}

document.addEventListener("languagechange", () => {
  updateStatusLabels();
  renderEmails(allEmails);
  if (document.querySelector("#account-google")) {
    setGmailCard(gmailAccount, gmailSync);
  }
});
updateStatusLabels();

async function loadEmails() {
  try {
    // The API decrypts message fields for this dashboard response only.
    allEmails = await apiRequest("/emails");
    setCounts(allEmails);
    renderEmails(allEmails);
    return true;
  } catch (error) {
    list.replaceChildren();
    const empty = createElement("div", "empty-state");
    empty.append(createElement("strong", "", window.translate("error.loadEmails")));
    empty.append(createElement("p", "", error.message));
    list.append(empty);
    return false;
  }
}

async function refreshEmails() {
  const button = document.querySelector("#refresh-button");
  button.disabled = true;
  button.classList.add("is-refreshing");
  try {
    if (await loadEmails()) setNotice(window.translate("emails.refreshed"));
  } finally {
    button.disabled = false;
    button.classList.remove("is-refreshing");
  }
}

function setGmailCard(account, sync) {
  gmailAccount = account;
  gmailSync = sync;
  const card = document.querySelector("#account-google");
  const state = card.querySelector(".connection-state");
  const email = card.querySelector(".connection-email");
  const connect = card.querySelector(".connect-button");
  const disconnectButton = card.querySelector(".disconnect-button");
  const oldProgress = card.querySelector(".sync-progress");
  if (oldProgress) oldProgress.remove();

  const connected = Boolean(account);
  const needsImapReconnect = connected && account.auth_method !== "oauth";
  const ready = connected && !needsImapReconnect;
  connect.hidden = ready;
  disconnectButton.hidden = !connected;
  disconnectButton.disabled = sync?.status === "running";
  scanMorePanel.hidden = !ready || !sync?.has_more;
  scanMoreButton.disabled = sync?.status === "running";
  scanMoreButton.textContent = window.translate("mail.scanNext", {
    count: Number(sync?.batch_number) > 0 ? 40 : 20
  });
  email.textContent = account?.email || "";
  state.className = "connection-state";

  if (needsImapReconnect) {
    state.textContent = window.translate("mail.reconnect");
    state.classList.add("syncing");
  } else if (sync?.status === "running") {
    state.textContent = window.translate("mail.syncing");
    state.classList.add("syncing");
    const progress = createElement(
      "span",
      "sync-progress",
      window.translate("mail.progress", { count: sync.processed || 0 })
    );
    card.querySelector(".connection-info").append(progress);
  } else if (sync?.status === "error") {
    state.textContent = window.translate("mail.syncFailed");
    state.classList.add("error");
    if (sync.error) {
      card.querySelector(".connection-info").append(createElement("span", "sync-progress", sync.error));
    }
  } else if (sync?.status === "complete") {
    state.textContent = window.translate("mail.synced", { count: sync.processed });
    state.classList.add("connected");
  } else if (ready) {
    state.textContent = window.translate("mail.connected");
    state.classList.add("connected");
  } else {
    state.textContent = window.translate("mail.notConnected");
  }
}

async function loadMailboxAccounts() {
  try {
    const [accounts, googleSync] = await Promise.all([
      apiRequest("/mail/accounts"),
      apiRequest("/mail/sync/google/status")
    ]);
    const account = accounts.find((item) => item.provider === "google");
    setGmailCard(account, googleSync);
    if (googleSync.status === "running" && !syncPollers.google) {
      syncPollers.google = window.setInterval(async () => {
        try {
          const updated = await apiRequest("/mail/sync/google/status");
          setGmailCard(account, updated);
          if (updated.status !== "running") {
            window.clearInterval(syncPollers.google);
            delete syncPollers.google;
            await loadEmails();
            if (updated.status === "complete") {
              setNotice(window.translate("notice.syncComplete", {
                count: updated.processed
              }));
            } else if (updated.status === "error") {
              setNotice(updated.error || window.translate("mail.syncFailed"), true);
            }
          }
        } catch (error) {
          setNotice(error.message, true);
        }
      }, 1500);
    }
  } catch (error) {
    setNotice(error.message, true);
  }
}

scanMoreButton.addEventListener("click", async () => {
  scanMoreButton.disabled = true;
  try {
    await apiRequest("/mail/sync/google", { method: "POST" });
    setNotice(window.translate("notice.syncStarted"));
    await loadMailboxAccounts();
  } catch (error) {
    setNotice(error.message, true);
    await loadMailboxAccounts();
  }
});

document.querySelectorAll(".disconnect-button").forEach((button) => {
  button.addEventListener("click", async () => {
    if (!window.confirm(window.translate("notice.disconnectConfirm"))) return;
    try {
      await apiRequest("/mail/accounts/google", { method: "DELETE" });
      await loadMailboxAccounts();
      setNotice(window.translate("notice.disconnected"));
    } catch (error) {
      setNotice(error.message, true);
    }
  });
});

document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelector(".nav-item.active")?.classList.remove("active");
    button.classList.add("active");
    activeStatus = button.dataset.status;
    renderEmails(allEmails);
    setNotice("");
  });
});

document.querySelector("#new-email-button").addEventListener("click", () => {
  formError.hidden = true;
  composeDialog.showModal();
  document.querySelector("#sender").focus();
});
document.querySelector("#close-dialog").addEventListener("click", () => composeDialog.close());
document.querySelector("#cancel-dialog").addEventListener("click", () => composeDialog.close());
document.querySelector("#refresh-button").addEventListener("click", refreshEmails);

document.querySelector("#clear-emails-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  if (!window.confirm(window.translate("emails.clearConfirm"))) return;
  button.disabled = true;
  try {
    const result = await apiRequest("/emails", { method: "DELETE" });
    allEmails = [];
    activeStatus = "all";
    document.querySelector(".nav-item.active")?.classList.remove("active");
    document.querySelector('[data-status="all"]')?.classList.add("active");
    setCounts(allEmails);
    renderEmails(allEmails);
    setNotice(window.translate("emails.clearSuccess", {
      count: result.deleted_count
    }));
  } catch (error) {
    setNotice(
      error.code === "sync_in_progress"
        ? window.translate("emails.syncActive")
        : error.message,
      true
    );
  } finally {
    button.disabled = false;
  }
});

emailForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  formError.hidden = true;
  submitButton.disabled = true;
  submitButton.textContent = window.translate("email.scanning");

  const formData = new FormData(emailForm);
  const email = Object.fromEntries(formData.entries());
  try {
    const result = await apiRequest("/emails", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(email)
    });
    emailForm.reset();
    composeDialog.close();
    activeStatus = "all";
    document.querySelector(".nav-item.active")?.classList.remove("active");
    document.querySelector('[data-status="all"]').classList.add("active");
    await loadEmails();
    setNotice(window.translate("email.scanComplete", {
      score: result.risk_score,
      status: statusLabels[result.status]
    }));
  } catch (error) {
    formError.textContent = error.message;
    formError.hidden = false;
  } finally {
    submitButton.disabled = false;
    submitButton.innerHTML = `${window.translate("scanEmail")} <span>→</span>`;
  }
});

loadEmails();
loadMailboxAccounts();
const query = new URLSearchParams(window.location.search);
if (query.has("connected")) {
  setNotice(window.translate("notice.connected"));
  window.history.replaceState({}, "", window.location.pathname);
} else if (query.has("mail_error")) {
  setNotice(query.get("mail_error"), true);
  window.history.replaceState({}, "", window.location.pathname);
}
