package com.example.securetransfer.browser;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.securetransfer.config.AppProperties;
import com.example.securetransfer.security.RateLimitHandshakeInterceptor;
import com.example.securetransfer.session.SessionManager;
import com.example.securetransfer.websocket.TransferWebSocketHandler;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.options.WaitForSelectorState;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

/**
 * Real-browser end-to-end test (headless Chromium via Playwright).
 *
 * Wiretaps everything the server receives — every HTTP request line + headers and every inbound
 * WebSocket frame — and asserts the plaintext secret and the link key never appear in any encoding.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, properties = {
        "server.port=18090", "app.allowed-origins=http://localhost:18090"})
class BrowserTransferIT {

    static final String BASE = "http://localhost:18090";
    static final List<String> HTTP_SEEN = new CopyOnWriteArrayList<>();
    static final List<String> WS_SEEN = new CopyOnWriteArrayList<>();

    @TestConfiguration
    static class Wiretap {
        @Bean
        @Primary
        TransferWebSocketHandler recordingHandler(SessionManager s, RateLimitHandshakeInterceptor l, AppProperties p) {
            return new TransferWebSocketHandler(s, l, p) {
                @Override
                protected void handleTextMessage(WebSocketSession session, TextMessage message) {
                    WS_SEEN.add(message.getPayload());
                    super.handleTextMessage(session, message);
                }
            };
        }

        @Bean
        FilterRegistrationBean<Filter> httpRecorder() {
            Filter f = (req, res, chain) -> {
                HttpServletRequest r = (HttpServletRequest) req;
                StringBuilder sb = new StringBuilder(r.getMethod()).append(' ').append(r.getRequestURL());
                if (r.getQueryString() != null) sb.append('?').append(r.getQueryString());
                for (String h : Collections.list(r.getHeaderNames())) {
                    sb.append('\n').append(h).append(": ").append(String.join(",", Collections.list(r.getHeaders(h))));
                }
                HTTP_SEEN.add(sb.toString());
                chain.doFilter(req, res);
            };
            FilterRegistrationBean<Filter> reg = new FilterRegistrationBean<>(f);
            reg.setOrder(Integer.MIN_VALUE);
            return reg;
        }
    }

    static Playwright playwright;
    static Browser browser;

    @Autowired SessionManager sessions;

    private static void shot(Page p, String name) {
        p.screenshot(new Page.ScreenshotOptions().setPath(Path.of("target/screenshots/" + name + ".png")).setFullPage(true));
    }

    @BeforeAll
    static void launch() {
        playwright = Playwright.create();
        browser = playwright.chromium().launch();
    }

    @AfterAll
    static void shutdown() {
        if (browser != null) browser.close();
        if (playwright != null) playwright.close();
    }

    @Test
    void secretTravelsEndToEndEncryptedAndServerNeverSeesPlaintextOrKey() {
        String secret = "sk_live_51H" + "-E2E-" + System.nanoTime() + "-pässwörd-🔐";

        try (BrowserContext senderCtx = browser.newContext();
             BrowserContext receiverCtx = browser.newContext(new Browser.NewContextOptions()
                     .setViewportSize(390, 844).setIsMobile(true).setHasTouch(true))) {

            // ---- Sender creates the transfer
            Page sender = senderCtx.newPage();
            List<String> consoleErrors = new CopyOnWriteArrayList<>();
            sender.onConsoleMessage(m -> { if ("error".equals(m.type())) consoleErrors.add(m.text()); });
            sender.navigate(BASE + "/");
            shot(sender, "1-sender-home");
            sender.fill("#secret", secret);
            sender.click("#create-btn");
            sender.waitForSelector("text=Waiting for receiver");
            shot(sender, "2-sender-waiting");
            String link = sender.textContent("#share-link");
            assertThat(link).matches("^" + BASE + "/t/[A-Za-z0-9_-]{22}#k=[A-Za-z0-9_-]{43}$");
            String keyB64u = link.substring(link.indexOf("#k=") + 3);

            // ---- Receiver (mobile) opens the link
            Page receiver = receiverCtx.newPage();
            receiver.onConsoleMessage(m -> { if ("error".equals(m.type())) consoleErrors.add(m.text()); });
            receiver.navigate(link);
            receiver.waitForSelector("text=Connected — waiting for sender");
            assertThat(receiver.url()).as("fragment removed from address bar").doesNotContain("#").doesNotContain(keyB64u);

            // ---- Sender sees verified receiver and sends
            sender.waitForSelector("[data-screen=connected]:not([hidden])");
            assertThat(sender.textContent("[data-screen=connected] .status")).contains("Receiver connected");
            shot(sender, "3-sender-connected");
            sender.click("#send-btn");

            // ---- Receiver decrypts
            receiver.waitForSelector("[data-screen=received]:not([hidden])");
            assertThat(receiver.textContent("#secret-out")).as("masked by default").doesNotContain(secret);
            receiver.click("#toggle-secret-btn");
            assertThat(receiver.textContent("#secret-out")).isEqualTo(secret);
            shot(receiver, "4-receiver-mobile-received");
            receiver.waitForSelector("#received-label:text('Transfer completed')");

            // ---- Sender gets authenticated delivery confirmation
            sender.waitForSelector("[data-screen=notice]:not([hidden])");
            assertThat(sender.textContent("#notice-label")).isEqualTo("Transfer completed");
            shot(sender, "5-sender-completed");
            assertThat(sender.inputValue("#secret")).as("sender textarea wiped").isEmpty();

            // ---- No browser persistence of secret or key
            for (Page p : List.of(sender, receiver)) {
                assertThat(p.evaluate("() => localStorage.length + sessionStorage.length")).isEqualTo(0);
                assertThat(p.evaluate("() => document.cookie")).isEqualTo("");
            }
            // ---- Mobile layout: no horizontal overflow
            assertThat((Boolean) receiver.evaluate(
                    "() => document.documentElement.scrollWidth <= document.documentElement.clientWidth")).isTrue();

            // ---- Session destroyed; link is single-use
            assertThat(sessions.size()).isZero();
            Page late = receiverCtx.newPage();
            late.navigate(link);
            late.waitForSelector("text=Cannot open transfer");

            assertThat(consoleErrors).as("no CSP violations / JS errors").isEmpty();

            // ---- Wiretap assertions: the server never received plaintext or key material
            byte[] key = Base64.getUrlDecoder().decode(keyB64u);
            List<String> forbidden = List.of(
                    secret,
                    "sk_live_51H",
                    keyB64u,
                    Base64.getEncoder().encodeToString(key),
                    Base64.getEncoder().withoutPadding().encodeToString(key),
                    HexFormat.of().formatHex(key),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(secret.getBytes()),
                    Base64.getEncoder().encodeToString(secret.getBytes()));
            assertThat(WS_SEEN).as("server saw WebSocket traffic").isNotEmpty();
            assertThat(WS_SEEN).anyMatch(f -> f.contains("\"ENCRYPTED_MESSAGE\""));
            assertThat(HTTP_SEEN).anyMatch(h -> h.contains("/t/"));
            for (String needle : forbidden) {
                for (String frame : WS_SEEN) assertThat(frame).doesNotContain(needle);
                for (String req : HTTP_SEEN) assertThat(req).doesNotContain(needle);
            }
            assertThat(HTTP_SEEN).noneMatch(h -> h.contains("#k="));
        }
    }

    @Test
    void autoSendDeliversWithoutPressingSend() {
        String secret = "auto-" + System.nanoTime();
        try (BrowserContext senderCtx = browser.newContext(); BrowserContext receiverCtx = browser.newContext()) {
            Page sender = senderCtx.newPage();
            sender.navigate(BASE + "/");
            sender.fill("#secret", secret);
            sender.click("label.switch");
            assertThat(sender.isChecked("#auto-send")).isTrue();
            sender.click("#create-btn");
            sender.waitForSelector("text=Waiting for receiver");
            assertThat(sender.textContent("#waiting-help")).contains("Auto-send is on");
            String link = sender.textContent("#share-link");

            Page receiver = receiverCtx.newPage();
            receiver.navigate(link);
            receiver.waitForSelector("[data-screen=received]:not([hidden])");
            receiver.click("#toggle-secret-btn");
            assertThat(receiver.textContent("#secret-out")).isEqualTo(secret);

            sender.waitForSelector("[data-screen=notice]:not([hidden])");
            assertThat(sender.textContent("#notice-label")).isEqualTo("Transfer completed");
            assertThat(sender.inputValue("#secret")).isEmpty();
        }
    }

    @Test
    void wrongKeyInLinkCannotJoin() {
        try (BrowserContext senderCtx = browser.newContext(); BrowserContext attackerCtx = browser.newContext()) {
            Page sender = senderCtx.newPage();
            sender.navigate(BASE + "/");
            sender.fill("#secret", "do-not-leak");
            sender.click("#create-btn");
            sender.waitForSelector("text=Waiting for receiver");
            String link = sender.textContent("#share-link");
            // Attacker knows the session ID but not the key.
            String forged = link.substring(0, link.indexOf("#k=") + 3) + "A".repeat(42) + "A";
            Page attacker = attackerCtx.newPage();
            attacker.navigate(forged);
            attacker.waitForSelector("text=This link is not valid for this transfer.");
            assertThat(sender.isVisible("[data-screen=waiting]")).as("sender unaffected").isTrue();
            sender.click("#cancel-waiting-btn");
            sender.waitForSelector("text=Transfer cancelled",
                    new Page.WaitForSelectorOptions().setState(WaitForSelectorState.VISIBLE));
        }
    }
}
