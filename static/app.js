const list = document.querySelector("#email-list");
const notice = document.querySelector("#notice");
const composeDialog = document.querySelector("#compose-dialog");
const emailForm = document.querySelector("#email-form");
const formError = document.querySelector("#form-error");
const submitButton = document.querySelector("#submit-button");

let activeStatus = "all";
let allEmails = [];
let syncPollers = {};

const statusLabels = {
  all: "All emails",
  inbox: "Inbox",
  review: "Needs review",
  quarantine: "Quarantine"
};

function setNotice(message, isError = false) {
  notice.textContent = message;
  notice.classList.toggle("error", isError);
  notice.hidden = !message;
}

async function apiRequest(url, options = {}) {
  const response = await fetch(url, options);
  const contentType = response.headers.get("content-type") || "";
  const result = contentType.includes("application/json")
    ? await response.json()
    : null;

  if (!response.ok) {
    throw new Error(result?.error || `Request failed (${response.status})`);
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
  if (!value) return "Date unavailable";
  const date = new Date(`${value.replace(" ", "T")}Z`);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short"
      }).format(date);
}

function statusBadge(status) {
  const label = statusLabels[status] || status;
  return createElement("span", `status-badge ${status}`, label);
}

function makeDetails(email) {
  const details = createElement("div", "email-details");
  details.hidden = true;

  const fields = [
    ["Email body", email.body || "No message body"],
    ["Detection reasons", null]
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
      reasons.append(createElement("span", "reason-chip", "No specific warning signals"));
    } else {
      for (const reason of reasonList) {
        reasons.append(createElement("span", "reason-chip", reason));
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
  senderBlock.append(createElement("div", "sender", email.sender || "Unknown sender"));
  senderBlock.append(createElement("div", "date", formatDate(email.created_at)));

  const subjectBlock = createElement("div", "subject-block");
  subjectBlock.append(createElement("div", "subject", email.subject || "(No subject)"));
  subjectBlock.append(createElement("div", "preview", (email.body || "").replace(/\s+/g, " ").trim() || "No message body"));

  const score = Number(email.risk_score) || 0;
  const riskBlock = createElement("div", "risk-block");
  const riskMeta = createElement("div", "risk-meta");
  riskMeta.append(createElement("span", "", "Risk score"));
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
  menu.title = "Show email details";
  menu.setAttribute("aria-expanded", "false");
  actions.append(menu);

  main.append(senderBlock, subjectBlock, riskBlock, actions);
  const details = makeDetails(email);
  menu.addEventListener("click", () => {
    details.hidden = !details.hidden;
    menu.setAttribute("aria-expanded", String(!details.hidden));
    menu.title = details.hidden ? "Show email details" : "Hide email details";
  });
  row.append(main, details);

  const controls = createElement("div", "row-controls");
  const statusSelect = document.createElement("select");
  statusSelect.className = "status-select";
  statusSelect.setAttribute("aria-label", `Move email from ${email.sender}`);
  for (const status of ["inbox", "review", "quarantine"]) {
    const option = document.createElement("option");
    option.value = status;
    option.textContent = `Move to ${statusLabels[status]}`;
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
      setNotice("Email status updated.");
      await loadEmails();
    } catch (error) {
      setNotice(error.message, true);
      statusSelect.value = email.status;
    }
  });
  const deleteButton = createElement("button", "delete-button", "Delete");
  deleteButton.type = "button";
  deleteButton.addEventListener("click", async () => {
    if (!window.confirm(`Delete the email from ${email.sender}? This cannot be undone.`)) return;
    try {
      await apiRequest(`/emails/${email.id}`, { method: "DELETE" });
      setNotice("Email deleted.");
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
    ? "A complete view of scanned messages"
    : `${visibleEmails.length} ${activeStatus === "review" ? "email(s) to review" : `email(s) in ${activeStatus}`}`;

  if (!visibleEmails.length) {
    const empty = createElement("div", "empty-state");
    empty.append(createElement("div", "empty-icon", "✦"));
    empty.append(createElement("strong", "", activeStatus === "all" ? "No emails scanned yet" : `No emails in ${statusLabels[activeStatus]}`));
    empty.append(createElement("p", "", "Scan an email to see its risk assessment here."));
    list.append(empty);
    return;
  }
  for (const email of visibleEmails) list.append(makeEmailRow(email));
}

async function loadEmails() {
  try {
    // The API decrypts message fields for this dashboard response only.
    allEmails = await apiRequest("/emails");
    setCounts(allEmails);
    renderEmails(allEmails);
  } catch (error) {
    list.replaceChildren();
    const empty = createElement("div", "empty-state");
    empty.append(createElement("strong", "", "Could not load emails"));
    empty.append(createElement("p", "", error.message));
    list.append(empty);
  }
}

function setGmailCard(account, sync) {
  const card = document.querySelector("#account-google");
  const state = card.querySelector(".connection-state");
  const email = card.querySelector(".connection-email");
  const connect = card.querySelector(".connect-button");
  const syncButton = card.querySelector(".sync-button");
  const disconnectButton = card.querySelector(".disconnect-button");
  const oldProgress = card.querySelector(".sync-progress");
  if (oldProgress) oldProgress.remove();

  const connected = Boolean(account);
  const needsImapReconnect = connected && account.auth_method !== "oauth";
  const ready = connected && !needsImapReconnect;
  connect.hidden = ready;
  syncButton.hidden = !ready;
  disconnectButton.hidden = !connected;
  disconnectButton.disabled = sync?.status === "running";
  email.textContent = account?.email || "";
  state.className = "connection-state";

  if (needsImapReconnect) {
    state.textContent = "Sign in with Google again";
    state.classList.add("syncing");
    syncButton.disabled = true;
  } else if (sync?.status === "running") {
    state.textContent = "Syncing mailbox...";
    state.classList.add("syncing");
    const progress = createElement("span", "sync-progress", `${sync.processed || 0} messages processed`);
    card.querySelector(".connection-info").append(progress);
    syncButton.disabled = true;
  } else if (sync?.status === "error") {
    state.textContent = "Sync failed";
    state.classList.add("error");
    syncButton.disabled = false;
    if (sync.error) {
      card.querySelector(".connection-info").append(createElement("span", "sync-progress", sync.error));
    }
  } else if (sync?.status === "complete") {
    state.textContent = `Connected · ${sync.processed} messages synced`;
    state.classList.add("connected");
    syncButton.disabled = false;
  } else if (ready) {
    state.textContent = "Connected";
    state.classList.add("connected");
    syncButton.disabled = false;
  } else {
    state.textContent = "Not connected";
    syncButton.disabled = false;
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
              setNotice(`Gmail sync complete: ${updated.processed} messages scanned.`);
            } else if (updated.status === "error") {
              setNotice(updated.error || "Mailbox sync failed.", true);
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

document.querySelectorAll(".sync-button").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      await apiRequest("/mail/sync/google", { method: "POST" });
      setNotice("Started scanning your Gmail mailbox. This may take a while for a large mailbox.");
      await loadMailboxAccounts();
    } catch (error) {
      setNotice(error.message, true);
    }
  });
});

document.querySelectorAll(".disconnect-button").forEach((button) => {
  button.addEventListener("click", async () => {
    if (!window.confirm("Disconnect Gmail? Previously imported emails will remain in this app.")) return;
    try {
      await apiRequest("/mail/accounts/google", { method: "DELETE" });
      await loadMailboxAccounts();
      setNotice("Gmail disconnected. Imported messages remain saved locally.");
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
document.querySelector("#refresh-button").addEventListener("click", loadEmails);

emailForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  formError.hidden = true;
  submitButton.disabled = true;
  submitButton.textContent = "Scanning...";

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
    setNotice(`Scan complete: risk score ${result.risk_score}/100 — ${statusLabels[result.status]}.`);
  } catch (error) {
    formError.textContent = error.message;
    formError.hidden = false;
  } finally {
    submitButton.disabled = false;
    submitButton.innerHTML = 'Scan email <span>→</span>';
  }
});

loadEmails();
loadMailboxAccounts();
const query = new URLSearchParams(window.location.search);
if (query.has("connected")) {
  setNotice("Gmail connected. Your mailbox is being scanned.");
  window.history.replaceState({}, "", window.location.pathname);
} else if (query.has("mail_error")) {
  setNotice(query.get("mail_error"), true);
  window.history.replaceState({}, "", window.location.pathname);
}
