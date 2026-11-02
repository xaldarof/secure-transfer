package com.example.securetransfer.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * HTTP hardening: strict CSP, no referrer, no caching, no framing.
 * No Spring Security dependency is needed: there are no accounts and no server-side auth state.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public FilterRegistrationBean<OncePerRequestFilter> securityHeadersFilter(AppProperties props) {
        String csp = buildCsp(props);
        OncePerRequestFilter filter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                    throws ServletException, IOException {
                res.setHeader("Content-Security-Policy", csp);
                res.setHeader("Referrer-Policy", "no-referrer");
                res.setHeader("X-Content-Type-Options", "nosniff");
                res.setHeader("X-Frame-Options", "DENY");
                res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
                res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
                res.setHeader("Permissions-Policy",
                        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()");
                res.setHeader("Cache-Control", "no-store");
                res.setHeader("Pragma", "no-cache");
                if (req.isSecure()) {
                    res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
                }
                chain.doFilter(req, res);
            }
        };
        FilterRegistrationBean<OncePerRequestFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
        reg.addUrlPatterns("/*");
        return reg;
    }

    /** connect-src lists the ws(s) equivalents of the allowed origins (older Safari ignores 'self' for ws). */
    static String buildCsp(AppProperties props) {
        Set<String> connect = new LinkedHashSet<>();
        connect.add("'self'");
        for (String origin : props.allowedOrigins()) {
            URI uri = URI.create(origin.trim());
            String scheme = "https".equalsIgnoreCase(uri.getScheme()) ? "wss" : "ws";
            connect.add(scheme + "://" + uri.getRawAuthority());
        }
        return "default-src 'none'; "
                + "script-src 'self'; "
                + "style-src 'self'; "
                + "img-src 'self'; "
                + "connect-src " + String.join(" ", connect) + "; "
                + "base-uri 'none'; "
                + "form-action 'none'; "
                + "frame-ancestors 'none'";
    }
}
