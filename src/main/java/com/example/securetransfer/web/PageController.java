package com.example.securetransfer.web;

import com.example.securetransfer.protocol.TransferMessage;
import java.util.Map;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the single static page. The URL fragment (#k=...) is never sent by browsers, so the server
 * only ever sees /t/{sessionId}.
 */
@RestController
public class PageController {

    private static final Resource INDEX = new ClassPathResource("static/index.html");

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public Resource home() {
        return INDEX;
    }

    @GetMapping(value = "/t/{sessionId}", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<Resource> transfer(@PathVariable String sessionId) {
        if (!TransferMessage.SESSION_ID.matcher(sessionId).matches()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(INDEX);
    }

    @GetMapping(value = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }
}
