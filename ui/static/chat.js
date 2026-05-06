(() => {
  const messagesEl = document.getElementById("messages");
  const form = document.getElementById("chatForm");
  const input = document.getElementById("composerInput");
  const sendBtn = document.getElementById("sendBtn");
  const logoutBtn = document.getElementById("logoutBtn");

  // ── Auto-grow textarea ───────────────────────────────────────────────
  const autoGrow = () => {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 160) + "px";
  };
  input.addEventListener("input", autoGrow);

  // ── Submit on Enter, newline on Shift+Enter ──────────────────────────
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      form.requestSubmit();
    }
  });

  // ── Minimal markdown renderer (bold, code, lists) ────────────────────
  const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));

  const renderMarkdown = (text) => {
    let out = escapeHtml(text);
    // Code blocks ```...```
    out = out.replace(/```([\s\S]*?)```/g, (_m, code) => `<pre>${code}</pre>`);
    // Inline `code`
    out = out.replace(/`([^`\n]+)`/g, "<code>$1</code>");
    // Bold **...**
    out = out.replace(/\*\*([^\*\n]+)\*\*/g, "<strong>$1</strong>");
    // Italic *...* (avoid matching inside bold)
    out = out.replace(/(^|[^*])\*([^\*\n]+)\*/g, "$1<em>$2</em>");

    // Bullet lists: lines starting with "- "
    const lines = out.split("\n");
    const blocks = [];
    let listBuf = [];
    const flushList = () => {
      if (listBuf.length) {
        blocks.push("<ul>" + listBuf.map((li) => `<li>${li}</li>`).join("") + "</ul>");
        listBuf = [];
      }
    };
    for (const line of lines) {
      const m = /^\s*-\s+(.*)$/.exec(line);
      if (m) {
        listBuf.push(m[1]);
      } else {
        flushList();
        blocks.push(line);
      }
    }
    flushList();
    return blocks.join("\n").replace(/\n/g, "<br />");
  };

  // ── Append a message ─────────────────────────────────────────────────
  const appendMessage = (role, text, opts = {}) => {
    const wrap = document.createElement("div");
    wrap.className = "msg " + (role === "user" ? "msg-user" : "msg-assistant");
    const bubble = document.createElement("div");
    bubble.className = "msg-bubble";
    if (opts.html) {
      bubble.innerHTML = text;
    } else {
      bubble.innerHTML = renderMarkdown(text);
    }
    wrap.appendChild(bubble);
    messagesEl.appendChild(wrap);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return wrap;
  };

  const appendTyping = () => appendMessage(
    "assistant",
    '<span class="typing"><span></span><span></span><span></span></span>',
    { html: true }
  );

  // ── Submit handler ───────────────────────────────────────────────────
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text) return;

    appendMessage("user", text);
    input.value = "";
    autoGrow();
    sendBtn.disabled = true;
    const typingNode = appendTyping();

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text }),
      });

      typingNode.remove();

      if (res.status === 401) {
        appendMessage("assistant", "Your session has expired. Redirecting to sign-in…");
        setTimeout(() => (window.location.href = "/login"), 1200);
        return;
      }

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        appendMessage("assistant", `**Error:** ${data.error || "Request failed."}`);
        return;
      }
      appendMessage("assistant", data.reply || "(no response)");
    } catch (err) {
      typingNode.remove();
      appendMessage("assistant", "**Network error** — could not reach the server.");
    } finally {
      sendBtn.disabled = false;
      input.focus();
    }
  });

  // ── Logout ───────────────────────────────────────────────────────────
  logoutBtn.addEventListener("click", async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch (_) { /* ignore */ }
    window.location.href = "/login";
  });
})();
