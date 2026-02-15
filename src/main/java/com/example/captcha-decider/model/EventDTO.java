package com.gmu.pragalv.capstone.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class EventDTO {

    private String sessionId;
    private long mouseMoveCount;
    private long keypressCount;
    private long elapsedMs;
    private String userAgent;
    private String page;
}
