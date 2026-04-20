package com.gmu.pragalv.capstone.model.accessor;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Component
@Slf4j
public class SessionAnalysisAccessor {

    private static final String DEFAULT_SESSION_ANALYSIS_URL = "http:///54.92.188.66:8000/analyze_session";

    private final RestTemplate restTemplate = new RestTemplate();
    private final String sessionAnalysisUrl;

    public SessionAnalysisAccessor(@Value("${security.session-analysis.url:" + DEFAULT_SESSION_ANALYSIS_URL + "}") String sessionAnalysisUrl) {
        this.sessionAnalysisUrl = normalizeSessionAnalysisUrl(sessionAnalysisUrl);
        if (!Objects.equals(this.sessionAnalysisUrl, sessionAnalysisUrl)) {
            log.warn("Normalized security.session-analysis.url from '{}' to '{}'", sessionAnalysisUrl, this.sessionAnalysisUrl);
        }
        log.info("Using analyze_session endpoint: {}", this.sessionAnalysisUrl);
    }

    public SessionDecision analyzeSession(Map<String, Object> payload, String sessionId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        log.info("SessionAnalysisAccessor.analyzeSession payload: {}" , payload);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    sessionAnalysisUrl,
                    HttpMethod.POST,
                    new HttpEntity<>(payload, headers),
                    new ParameterizedTypeReference<>() {
                    }
            );
            log.info("SessionAnalysisAccessor.analyzeSession response: {}" , response);
            Map<String, Object> body = response.getBody();
            if (body == null || !(body.get("decision") instanceof Map<?, ?> decisionMap)) {
                return null;
            }
            SessionDecision decision = new SessionDecision();
            Object captchaObj = decisionMap.get("captcha");
            if (captchaObj instanceof Boolean captchaValue) {
                decision.captcha = captchaValue;
            }
            Object riskScoreObj = decisionMap.get("risk_score");
            if (riskScoreObj instanceof Number scoreValue) {
                decision.riskScore = scoreValue.intValue();
            }
            Object reasonsObj = decisionMap.get("reasons");
            if (reasonsObj instanceof List<?> reasonsList) {
                decision.reasons = reasonsList.stream().map(String::valueOf).toList();
            }
            return decision;
        } catch (RestClientException ex) {
            log.warn("analyze_session call failed, keeping local ALLOW decision. sessionId={}, url={}", sessionId, sessionAnalysisUrl, ex);
            return null;
        }
    }

    private String normalizeSessionAnalysisUrl(String configuredUrl) {
        if (!StringUtils.hasText(configuredUrl)) {
            return DEFAULT_SESSION_ANALYSIS_URL;
        }

        String normalized = configuredUrl.trim();
        normalized = normalized.replaceFirst("^(https?:)/{3,}", "$1//");
        if (!normalized.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) {
            normalized = "http://" + normalized.replaceFirst("^/+", "");
        }

        try {
            URI uri = URI.create(normalized);
            if (!StringUtils.hasText(uri.getHost())) {
                throw new IllegalArgumentException("host missing");
            }
            return normalized;
        } catch (IllegalArgumentException ex) {
            log.warn("Invalid security.session-analysis.url '{}', falling back to '{}'", configuredUrl, DEFAULT_SESSION_ANALYSIS_URL);
            return DEFAULT_SESSION_ANALYSIS_URL;
        }
    }

    @Data
    public static class SessionDecision {
        private Boolean captcha;
        private Integer riskScore;
        private List<String> reasons;
    }
}
