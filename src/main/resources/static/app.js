(() => {
    const form = document.getElementById("contact-form");
    const statusEl = document.getElementById("status");
    const modal = document.getElementById("captcha-modal");
    const captchaCheckbox = document.getElementById("captcha-checkbox");
    const captchaSubmit = document.getElementById("captcha-submit");
    const captchaText = document.getElementById("captcha-text");
    const captchaCompletedField = document.getElementById("captchaCompleted");

    const sessionId = ensureSessionId();
    document.getElementById("sessionId").value = sessionId;
    document.getElementById("timezoneOffset").value = String(new Date().getTimezoneOffset());
    document.getElementById("screenHeight").value = String(window.screen.height);
    document.getElementById("screenWidth").value = String(window.screen.width);

    let mouseMoves = 0;
    let keyPresses = 0;
    let lastHeartbeat = Date.now();
    let pendingPayload = null;

    window.addEventListener("mousemove", () => mouseMoves++);
    window.addEventListener("keydown", () => keyPresses++);

    form.addEventListener("submit", (evt) => {
        evt.preventDefault();
        const payload = buildPayload(form);
        pendingPayload = payload;
        submitPayload(payload, false);
    });

    captchaSubmit.addEventListener("click", () => {
        if (!captchaCheckbox.checked) {
            setStatus("Please confirm you are human to continue.", "warn");
            return;
        }
        captchaCompletedField.value = "true";
        if (pendingPayload) {
            submitPayload({ ...pendingPayload, captchaCompleted: true }, true);
        }
        closeCaptcha();
        captchaCheckbox.checked = false;
    });

    setInterval(() => {
        const now = Date.now();
        const elapsedMs = now - lastHeartbeat;
        lastHeartbeat = now;
        sendHeartbeat({
            sessionId,
            mouseMoveCount: mouseMoves,
            keypressCount: keyPresses,
            elapsedMs,
            userAgent: navigator.userAgent,
            page: location.pathname
        });
        mouseMoves = 0;
        keyPresses = 0;
    }, 5000);

    function ensureSessionId() {
        const existing = readCookie("cds_session");
        if (existing) return existing;
        const value = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
        document.cookie = `cds_session=${value}; path=/; max-age=${60 * 60 * 24 * 7}`;
        return value;
    }

    function readCookie(name) {
        const match = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
        return match ? match[2] : null;
    }

    function buildPayload(formEl) {
        const data = new FormData(formEl);
        const payload = {};
        for (const [k, v] of data.entries()) {
            payload[k] = v;
        }
        payload.userAgent = navigator.userAgent;
        payload.pageUrl = location.href;
        payload.sessionId = sessionId;
        return payload;
    }

    async function submitPayload(payload, alreadySolvedCaptcha) {
        setStatus("Submitting...", "muted");
        try {
            const res = await fetch("/api/v1/form", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            handleDecision(data, alreadySolvedCaptcha);
        } catch (err) {
            console.error(err);
            setStatus("Network error while submitting. Try again.", "error");
        } finally {
            captchaCompletedField.value = "false";
        }
    }

    function handleDecision(resp, alreadySolvedCaptcha) {
        const decision = resp.result;
        if (decision === "ALLOW") {
            setStatus("Request accepted.", "ok");
            form.reset();
            pendingPayload = null;
        } else if (decision === "CAPTCHA" && !alreadySolvedCaptcha) {
            openCaptcha(resp.message || "Unusual activity detected. Please confirm.");
        } else if (decision === "DENY") {
            setStatus(resp.message || "Request denied.", "error");
        } else {
            setStatus("Unexpected response.", "warn");
        }
    }

    async function sendHeartbeat(payload) {
        try {
            await fetch("/api/v1/event", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
        } catch (err) {
            // ignore transient failures
        }
    }

    function openCaptcha(message) {
        captchaText.textContent = message;
        modal.classList.remove("hidden");
    }

    function closeCaptcha() {
        modal.classList.add("hidden");
    }

    function setStatus(msg, type) {
        statusEl.textContent = msg;
        statusEl.className = `status status--${type || "muted"}`;
    }
})();
