package org.tsicoop.dxnode.framework;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Server-side gate for the static admin console pages (dashboard, contracts,
 * partners, transfers, ...).
 *
 * The console pages used to be served unconditionally to any HTTP client; the
 * only login check was client-side JS reading localStorage after the page had
 * already been delivered. This filter runs before the default servlet dispatches
 * the file and requires a valid admin session JWT, carried in an HttpOnly cookie
 * so plain browser navigation (which cannot send an Authorization header) can
 * present it. Without one the user is redirected to the login page.
 *
 * It does not change API authentication: /api/admin/* continues to be validated
 * by InterceptingFilter on every request via the Authorization header.
 */
public class ConsoleAuthFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String token = InputProcessor.readConsoleSessionCookie(req);
        if (token == null || !JWTUtil.isTokenValid(token)) {
            res.sendRedirect("/index.html");
            return;
        }

        // Authenticated page loads must not be cached by shared caches / back button replay.
        res.setHeader("Cache-Control", "no-store");
        chain.doFilter(request, response);
    }
}
