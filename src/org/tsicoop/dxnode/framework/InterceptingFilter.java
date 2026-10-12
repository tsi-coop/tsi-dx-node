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

    /**
     * The P2P handshake header only ever bypasses admin JWT authentication for the
     * inbound peer-to-peer functions below, on the route that serves each one.
     * Every other admin function (users, apps/API keys, settings, node config,
     * initiating contracts or transfers, ...) always requires an admin JWT, even
     * if the header is present. Keep in sync with the functions Partners,
     * DataContract, TransferEngine and SyncEngine send to peers.
     */
    private static final Map<String, Set<String>> P2P_ALLOWED_FUNCS = new HashMap<>();
    static {
        P2P_ALLOWED_FUNCS.put("/api/admin/partners", new HashSet<>(Arrays.asList(
                "probe", "receive_partnership_proposal",
                "receive_termination_request", "receive_termination_finalization")));
        P2P_ALLOWED_FUNCS.put("/api/admin/contracts", new HashSet<>(Arrays.asList(
                "receive_contract_invitation", "confirm_invitation", "decline_invitation",
                "notify_participant_suspended", "notify_contract_suspended", "receive_contract_update")));
        P2P_ALLOWED_FUNCS.put("/api/admin/transfers", new HashSet<>(Arrays.asList(
                "receive_transfer_stream", "receive_sync_request")));
    }

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
                         && !servletPath.contains("api/admin/passwordreset")
                         && !servletPath.contains("api/admin/register")) {
                     
                     // 1. P2P PROTOCOL BYPASS
                     // If the request comes from a trusted partner node using the handshake token,
                     // we bypass the requirement for an administrative user JWT.
                     String p2pHeader = req.getHeader("X-DX-P2P-HANDSHAKE");
                     if (P2P_HANDSHAKE_TOKEN.equals(p2pHeader) && isAllowedP2PCall(req, servletPath.trim())) {
                         // The header only routes the call; the peer is authenticated by its signature.
                         String reason = PeerAuth.verify(req, peerFunction(req), peerBody(req));
                         if (reason != null) {
                             res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized - " + reason);
                             return;
                         }
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

                     // Instantiate the Action class (e.g., DataContract)
                     Action action = ((Action) Class.forName(classname).getConstructor().newInstance());
                     
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

    /**
     * True only if every function selector on the request (the X-DX-FUNCTION header,
     * which some actions prefer, and the body _func) names an inbound P2P function
     * allowed on this route. Both are checked because actions differ in which one
     * they honour, so a mismatch must not let an admin function ride a peer header.
     */
    private boolean isAllowedP2PCall(HttpServletRequest req, String path) {
        Set<String> allowed = P2P_ALLOWED_FUNCS.get(path);
        if (allowed == null) return false;

        String headerFunc = req.getHeader("X-DX-FUNCTION");
        String bodyFunc = null;
        InputProcessor.processInput(req, null); // idempotent; body is re-read via request attribute
        try {
            org.json.simple.JSONObject input = InputProcessor.getInput(req);
            if (input != null && input.get("_func") instanceof String) bodyFunc = (String) input.get("_func");
        } catch (Exception ignored) {
        }

        if (headerFunc == null && bodyFunc == null) return false;
        if (headerFunc != null && !allowed.contains(headerFunc.trim().toLowerCase())) return false;
        if (bodyFunc != null && !allowed.contains(bodyFunc.trim().toLowerCase())) return false;
        return true;
    }

    /** The function a peer request names: body _func, else the X-DX-FUNCTION header. */
    private String peerFunction(HttpServletRequest req) {
        try {
            org.json.simple.JSONObject input = InputProcessor.getInput(req);
            if (input != null && input.get("_func") instanceof String) return ((String) input.get("_func")).trim();
        } catch (Exception ignored) {
        }
        String h = req.getHeader("X-DX-FUNCTION");
        return h == null ? "" : h.trim();
    }

    private String peerBody(HttpServletRequest req) {
        Object raw = req.getAttribute(InputProcessor.REQUEST_DATA);
        return raw == null ? "" : raw.toString();
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        SystemConfig.loadProcessors(filterConfig.getServletContext());
        SystemConfig.loadAppConfig(filterConfig.getServletContext());
        JSONSchemaValidator.createInstance(filterConfig.getServletContext());
        System.out.println("TSI DX Node Intercepting Filter Initialized");
    }
}