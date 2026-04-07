package org.tsicoop.dxnode.framework;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.*;

/**
 * Global request filter for the TSI DX Node.
 * Handles CORS, character encoding, and protocol-level authorization bypass.
 */
public class InterceptingFilter implements Filter {

    private static final String URL_DELIMITER = "/";
    private static final String ADMIN_URI = "admin";
    private static final String CLIENT_URI = "client";
    
    // Must match the token defined in DataContract.java
    private static final String P2P_HANDSHAKE_TOKEN = "DX-P2P-PROTOCOL-V1";

    @Override
    public void destroy() {
        // Resources cleanup
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String method = req.getMethod();
        String servletPath = req.getServletPath();
        String classname = null;
        Properties apiRegistry = null;
        boolean validheader = true;

        // Standard Response Headers
        res.setCharacterEncoding("UTF-8");
        res.setContentType("application/json");

        apiRegistry = SystemConfig.getProcessorConfig();

        if (apiRegistry.containsKey(servletPath.trim())) {
            StringTokenizer strTok = new StringTokenizer(servletPath, URL_DELIMITER);
            strTok.nextToken(); // skip api keyword
            String uriIdentifier = strTok.nextToken();
            
            if (!(uriIdentifier.equalsIgnoreCase(ADMIN_URI) || uriIdentifier.equalsIgnoreCase(CLIENT_URI))){
                res.sendError(400);
                return;
            }

             try {
                 // AUTHENTICATION GATEKEEPER
                 if(servletPath.contains("api/admin")
                         && !servletPath.contains("api/admin/login")
                         && !servletPath.contains("api/admin/register")) {
                     
                     // 1. P2P PROTOCOL BYPASS
                     // If the request comes from a trusted partner node using the handshake token,
                     // we bypass the requirement for an administrative user JWT.
                     String p2pHeader = req.getHeader("X-DX-P2P-HANDSHAKE");
                     if (P2P_HANDSHAKE_TOKEN.equals(p2pHeader)) {
                         validheader = true;
                     } else {
                         // 2. Standard Admin JWT validation
                         validheader = InputProcessor.processAdminHeader(req, res);
                     }
                 } else if(servletPath.contains("api/client")) {
                     validheader = true;
                 }

                 if(!validheader) {
                     // If validation failed and InputProcessor hasn't already sent an error
                     if (!res.isCommitted()) {
                        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized - Protocol identity rejected.");
                     }
                 } else {
                     // REQUEST EXECUTION
                     InputProcessor.processInput(req, res);
                     classname = apiRegistry.getProperty(servletPath.trim());
                     
                     if (classname == null || method == null) {
                         res.sendError(400);
                         return;
                     }

                     // Instantiate the REST action class (e.g., DataContract)
                     REST action = ((REST) Class.forName(classname).getConstructor().newInstance());
                     
                     // Action-level validation (checks params, schema, and re-verifies P2P token)
                     if (action.validate(method, req, res)) {
                         if (method.equalsIgnoreCase("GET")) {
                             action.get(req, res);
                         } else if (method.equalsIgnoreCase("POST")) {
                             action.post(req, res);
                         } else if (method.equalsIgnoreCase("PUT")) {
                             action.put(req, res);
                         } else if (method.equalsIgnoreCase("DELETE")) {
                             action.delete(req, res);
                         } else {
                             res.sendError(400);
                         }
                     }
                 }
            } catch (Exception e) {
                e.printStackTrace();
                if (!res.isCommitted()) res.sendError(500, "Internal Filter Error: " + e.getMessage());
            }
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        SystemConfig.loadProcessors(filterConfig.getServletContext());
        SystemConfig.loadAppConfig(filterConfig.getServletContext());
        JSONSchemaValidator.createInstance(filterConfig.getServletContext());
        System.out.println("TSI DX Node Intercepting Filter Initialized");
    }
}