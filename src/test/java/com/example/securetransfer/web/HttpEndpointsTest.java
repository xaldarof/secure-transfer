package com.example.securetransfer.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HttpEndpointsTest {

    @LocalServerPort int port;
    private final HttpClient http = HttpClient.newHttpClient();

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void homeServedWithStrictHeaders() throws Exception {
        HttpResponse<String> r = get("/");
        assertThat(r.statusCode()).isEqualTo(200);
        assertThat(r.body()).contains("Create Secure Transfer");
        String csp = r.headers().firstValue("Content-Security-Policy").orElseThrow();
        assertThat(csp).contains("default-src 'none'", "script-src 'self'", "frame-ancestors 'none'")
                .doesNotContain("unsafe-inline", "unsafe-eval");
        assertThat(r.headers().firstValue("Referrer-Policy")).contains("no-referrer");
        assertThat(r.headers().firstValue("Cache-Control")).contains("no-store");
        assertThat(r.headers().firstValue("X-Frame-Options")).contains("DENY");
        assertThat(r.headers().firstValue("Set-Cookie")).isEmpty();
    }

    @Test
    void transferPage() throws Exception {
        assertThat(get("/t/AAAAAAAAAAAAAAAAAAAAAA").statusCode()).isEqualTo(200);
        assertThat(get("/t/../../etc").statusCode()).isIn(400, 404);
        assertThat(get("/t/bad").statusCode()).isEqualTo(404);
    }

    @Test
    void healthAndStaticAssets() throws Exception {
        assertThat(get("/health").body()).contains("UP");
        assertThat(get("/js/crypto.js").statusCode()).isEqualTo(200);
        assertThat(get("/js/app.js").statusCode()).isEqualTo(200);
        assertThat(get("/css/style.css").statusCode()).isEqualTo(200);
    }

    @Test
    void errorsDoNotLeakDetails() throws Exception {
        HttpResponse<String> r = get("/does-not-exist");
        assertThat(r.statusCode()).isEqualTo(404);
        assertThat(r.body()).doesNotContain("Exception", "at com.", "trace");
    }
}
