package com.gmu.pragalv.capstone.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@Builder
@NoArgsConstructor
public class RequestDTO {

    private String firstName;
    private String lastName;
    private String emailId;
    private String text;

    // client fingerprint
    private String sessionId;
    private Integer timezoneOffset;
    private Integer screenHeight;
    private Integer screenWidth;
    private String userAgent;
    private String pageUrl;

    // honeypots (should remain empty for humans)
    @JsonProperty("hp_emailId")
    private String honeypotEmailId;
    @JsonProperty("hp_comment")
    private String honeypotComment;

    // captcha confirmation from FE checkbox
    private boolean captchaCompleted;

}
