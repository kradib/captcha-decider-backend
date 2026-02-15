package com.gmu.pragalv.capstone.service;

import com.gmu.pragalv.capstone.model.EventDTO;
import com.gmu.pragalv.capstone.model.RequestDTO;
import com.gmu.pragalv.capstone.model.SecurityResult;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SecurityService {

    private static final double MAX_MOUSE_RATE_PER_SEC = 20.0; // unusually high
    private static final double MAX_KEY_RATE_PER_SEC = 4.0;    // unusually high typing

    private final Map<String, SessionRisk> sessions = new ConcurrentHashMap<>();

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

            if (mouseRate > MAX_MOUSE_RATE_PER_SEC || keyRate > MAX_KEY_RATE_PER_SEC) {
                risk.flag("Unusually high interaction rate");
            }
        }

        return risk.requiresCaptcha ? SecurityResult.CAPTCHA : SecurityResult.ALLOW;
    }

    private boolean ipChanged(String currentIp, SessionRisk risk) {
        if (!Objects.equals(risk.initialIp, currentIp)) {
            risk.initialIp = currentIp;
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
        private Instant lastSeen;

        SessionRisk(String ip) {
            this.initialIp = ip;
            this.lastSeen = Instant.now();
        }

        void flag(String reason) {
            this.requiresCaptcha = true;
        }

        void touch() {
            this.lastSeen = Instant.now();
        }
    }
}
