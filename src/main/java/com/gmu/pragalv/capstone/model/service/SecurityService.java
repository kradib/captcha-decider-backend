package com.gmu.pragalv.capstone.model.service;

import com.gmu.pragalv.capstone.model.accessor.SessionAnalysisAccessor;
import com.gmu.pragalv.capstone.model.model.EventDTO;
import com.gmu.pragalv.capstone.model.model.RequestDTO;
import com.gmu.pragalv.capstone.model.model.SecurityResult;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SecurityService {

    private static final double MAX_MOUSE_RATE_PER_SEC = 20.0; // unusually high
    private static final double MAX_KEY_RATE_PER_SEC = 4.0;    // unusually high typing

    private final Map<String, SessionRisk> sessions = new ConcurrentHashMap<>();
    private final SessionAnalysisAccessor sessionAnalysisAccessor;

    public SecurityService(SessionAnalysisAccessor sessionAnalysisAccessor) {
        this.sessionAnalysisAccessor = sessionAnalysisAccessor;
    }

    public SecurityResult evaluateForm(RequestDTO dto, HttpServletRequest request) {
        String sessionId = dto.getSessionId();
        String ip = clientIp(request);

        if (!StringUtils.hasText(sessionId)) {
            return SecurityResult.CAPTCHA;
        }

        SessionRisk risk = sessions.computeIfAbsent(sessionId, s -> new SessionRisk(ip));
        risk.touch();

        if (ipChanged(ip, risk)) {
            risk.flag("IP changed during session");
        }

        if (StringUtils.hasText(dto.getHoneypotEmailId()) || StringUtils.hasText(dto.getHoneypotComment())) {
            risk.flag("Honeypot field populated");
        }

        if (!StringUtils.hasText(dto.getUserAgent())) {
            risk.flag("Missing user-agent");
        }

        if (risk.requiresCaptcha && !dto.isCaptchaCompleted()) {
            return SecurityResult.CAPTCHA;
        }


        SessionAnalysisAccessor.SessionDecision decision = sessionAnalysisAccessor.analyzeSession(
                buildSessionAnalysisPayload(dto, risk),
                dto.getSessionId()
        );
        if (decision != null && Boolean.TRUE.equals(decision.getCaptcha())) {
            risk.flag("External analyze_session decision");
            return SecurityResult.CAPTCHA;
        }

        if (risk.requiresCaptcha) {
            risk.requiresCaptcha = false;
        }

        return SecurityResult.ALLOW;
    }

    public SecurityResult handleEvent(EventDTO dto, HttpServletRequest request) {
        String sessionId = dto.getSessionId();
        String ip = clientIp(request);

        if (!StringUtils.hasText(sessionId)) {
            return SecurityResult.CAPTCHA;
        }

        SessionRisk risk = sessions.computeIfAbsent(sessionId, s -> new SessionRisk(ip));
        risk.touch();

        if (ipChanged(ip, risk)) {
            risk.flag("IP changed during session");
        }

        if (dto.getElapsedMs() > 0) {
            double seconds = dto.getElapsedMs() / 1000.0;
            double mouseRate = dto.getMouseMoveCount() / seconds;
            double keyRate = dto.getKeypressCount() / seconds;
            risk.recordInteraction(dto.getMouseMoveCount(), dto.getKeypressCount(), dto.getElapsedMs(), mouseRate, keyRate);

            if (mouseRate > MAX_MOUSE_RATE_PER_SEC || keyRate > MAX_KEY_RATE_PER_SEC) {
                risk.flag("Unusually high interaction rate");
            }
        } else {
            risk.recordInteraction(dto.getMouseMoveCount(), dto.getKeypressCount(), dto.getElapsedMs(), 0.0, 0.0);
        }

        return risk.requiresCaptcha ? SecurityResult.CAPTCHA : SecurityResult.ALLOW;
    }

    private Map<String, Object> buildSessionAnalysisPayload(RequestDTO dto, SessionRisk risk) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("session_duration_ms", risk.sessionDurationMs());
        payload.put("form_fill_ms", risk.sessionDurationMs());
        payload.put("mousemove_count", risk.totalMouseMoves);
        payload.put("keyboard_click_count", risk.totalKeypresses);
        payload.put("avg_keydown_interval_ms", risk.keyRateToAvgKeydownIntervalMs());
        payload.put("mouseRate", risk.lastMouseRatePerSec);
        payload.put("keyRate", risk.lastKeyRatePerSec);
        payload.put("headless_suspected", isHeadless(dto.getUserAgent()));
        payload.put("webdriver_true", false);
        payload.put("client_webdriver", false);
        payload.put("ip_change_during_session", risk.ipChangedDuringSession);
        return payload;
    }

    private boolean isHeadless(String userAgent) {
        if (!StringUtils.hasText(userAgent)) {
            return false;
        }
        return userAgent.toLowerCase().contains("headless");
    }

    private boolean ipChanged(String currentIp, SessionRisk risk) {
        if (!Objects.equals(risk.initialIp, currentIp)) {
            risk.initialIp = currentIp;
            risk.ipChangedDuringSession = true;
            return true;
        }
        return false;
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(forwarded)) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private static class SessionRisk {
        private String initialIp;
        private boolean requiresCaptcha;
        private boolean ipChangedDuringSession;
        private Instant lastSeen;
        private final Instant startedAt;
        private long totalMouseMoves;
        private long totalKeypresses;
        private long totalElapsedMs;
        private double lastMouseRatePerSec;
        private double lastKeyRatePerSec;

        SessionRisk(String ip) {
            this.initialIp = ip;
            this.startedAt = Instant.now();
            this.lastSeen = Instant.now();
        }

        void flag(String reason) {
            this.requiresCaptcha = true;
        }

        void touch() {
            this.lastSeen = Instant.now();
        }

        void recordInteraction(long mouseMoves, long keypresses, long elapsedMs, double mouseRatePerSec, double keyRatePerSec) {
            this.totalMouseMoves += Math.max(0, mouseMoves);
            this.totalKeypresses += Math.max(0, keypresses);
            this.totalElapsedMs += Math.max(0, elapsedMs);
            this.lastMouseRatePerSec = Math.max(0.0, mouseRatePerSec);
            this.lastKeyRatePerSec = Math.max(0.0, keyRatePerSec);
        }

        long sessionDurationMs() {
            long eventBased = Math.max(0L, this.totalElapsedMs);
            if (eventBased > 0) {
                return eventBased;
            }
            return Math.max(0L, Instant.now().toEpochMilli() - this.startedAt.toEpochMilli());
        }

        long keyRateToAvgKeydownIntervalMs() {
            if (lastKeyRatePerSec <= 0.0) {
                return 0L;
            }
            return (long) (1000.0 / lastKeyRatePerSec);
        }
    }

}
