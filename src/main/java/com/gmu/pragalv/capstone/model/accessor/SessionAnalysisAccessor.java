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
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class SessionAnalysisAccessor {

    private final RestTemplate restTemplate = new RestTemplate();
    private final String sessionAnalysisUrl;

    public SessionAnalysisAccessor(@Value("${security.session-analysis.url:http://18.232.129.213:8000/analyze_session}") String sessionAnalysisUrl) {
        this.sessionAnalysisUrl = sessionAnalysisUrl;
    }

    public SessionDecision analyzeSession(Map<String, Object> payload, String sessionId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    sessionAnalysisUrl,
                    HttpMethod.POST,
                    new HttpEntity<>(payload, headers),
                    new ParameterizedTypeReference<>() {
                    }
            );
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
            log.warn("analyze_session call failed, keeping local ALLOW decision. sessionId={}", sessionId, ex);
            return null;
        }
    }

    @Data
    public static class SessionDecision {
        private Boolean captcha;
        private Integer riskScore;
        private List<String> reasons;
    }
}
