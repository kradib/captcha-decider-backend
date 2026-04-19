package com.gmu.pragalv.capstone.model.controller;


import com.gmu.pragalv.capstone.model.model.EventDTO;
import com.gmu.pragalv.capstone.model.model.RequestDTO;
import com.gmu.pragalv.capstone.model.model.ResponseDTO;
import com.gmu.pragalv.capstone.model.model.SecurityResult;
import com.gmu.pragalv.capstone.model.service.SecurityService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
@CrossOrigin(origins = "*") // allow all origins
@Slf4j
@RequiredArgsConstructor
public class FormController {

    private final SecurityService securityService;

    @PostMapping("/form")
    public ResponseEntity<ResponseDTO> acceptForm(@RequestBody RequestDTO requestDTO,
                                                  HttpServletRequest servletRequest) {
        log.info("Received form request : {}", requestDTO);
        SecurityResult result = securityService.evaluateForm(requestDTO, servletRequest);
        return ResponseEntity.ok(ResponseDTO.builder()
                .result(result)
                .message(result == SecurityResult.CAPTCHA ? "Captcha required due to unusual activity" : "OK")
                .build());
    }

    @PostMapping("/event")
    public ResponseEntity<ResponseDTO> recordEvent(@RequestBody EventDTO eventDTO,
                                                   HttpServletRequest servletRequest) {
        log.info("received event {}", eventDTO);
        SecurityResult result = securityService.handleEvent(eventDTO, servletRequest);
        return ResponseEntity.ok(ResponseDTO.builder()
                .result(result)
                .message(result == SecurityResult.CAPTCHA ? "Suspicious activity detected" : "OK")
                .build());
    }

}
