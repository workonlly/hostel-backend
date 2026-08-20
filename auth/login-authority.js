const express = require('express');
const router = express.Router();
const bcrypt = require("bcryptjs");
const pool = require("../db/db");
const { authLimiter } = require("../middleware/rateLimiter");
const {
    getClientIp,
    getRefreshTokenExpiry,
    hashRefreshToken,
    generateRefreshToken,
    generateAccessToken,
    getCookieOptions
} = require("../utils/authHelpers");
const { createSession, checkSessionConflict, getActiveSessionFromRequest, deactivateUserSessions } = require("../utils/sessionService");

router.post("/login", authLimiter, async (req, res) => {
    try {
        const { email, password, forceLogout } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "Email and password are required" });
        }

        const authCheck = await pool.query("SELECT * FROM authority WHERE email = $1", [email]);
        if (authCheck.rows.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        const user = authCheck.rows[0];

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        // Check if approved (chief-wardens are always approved)
        const normalizedRole = user.status.toLowerCase().replace(/[\s_]+/g, "-");
        
        if (normalizedRole !== 'chief-warden' && !user.approved_by) {
            return res.status(403).json({ success: false, message: "Account not approved by admin yet." });
        }

        // Check for session conflicts (e.g., student session already active in this browser)
        const conflict = await checkSessionConflict(req, normalizedRole, user.id, { forceLogout: Boolean(forceLogout) });
        if (conflict.hasConflict) {
            return res.status(409).json({
                success: false,
                conflict: true,
                currentRole: conflict.currentRole,
                message: conflict.message
            });
        }

        // Deactivate previous active sessions for this authority user on fresh login
        const actorType = normalizedRole === 'guard' ? 'GUARD' : 'AUTHORITY';
        await deactivateUserSessions(user.id, actorType);

        // 1. Prepare session details
        const refreshTtl = getRefreshTokenExpiry(normalizedRole);
        const refreshToken = generateRefreshToken();
        const refreshTokenHash = await hashRefreshToken(refreshToken);
        const refreshExpiresAt = new Date(Date.now() + refreshTtl);
        const ipAddress = getClientIp(req);
        const userAgent = req.headers["user-agent"] || null;

        // 2. Create user_session in DB
        const session = await createSession({
            actorId: user.id,
            actorType,
            ipAddress,
            userAgent,
            role: normalizedRole,
            refreshTokenHash,
            refreshExpiresAt,
            machineId: req.body.machineId || null
        });

        // 3. Generate short-lived Access Token containing sessionId
        const accessToken = generateAccessToken({
            id: user.id,
            email: user.email,
            role: normalizedRole,
            hostel: user.hostel,
            status: normalizedRole,
            sessionId: session.id
        });

        delete user.password;
        
        // Ensure the frontend receives the normalized role
        user.status = normalizedRole;
        user.role = normalizedRole;

        // Set persistent HttpOnly cookies
        const cookieOpts = getCookieOptions(req, refreshTtl);
        res.cookie("token", accessToken, cookieOpts);
        res.cookie("accessToken", accessToken, cookieOpts);
        res.cookie("refreshToken", refreshToken, cookieOpts);

        return res.status(200).json({
            success: true,
            sessionId: session.id,
            token: accessToken,
            accessToken: accessToken,
            refreshToken: refreshToken,
            user
        });
    } catch (err) {
        console.error("Authority login error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

/**
 * GET /api/authority/me - Validates existing authority session and auto-refreshes token if needed
 */
router.get("/me", async (req, res) => {
    try {
        const active = await getActiveSessionFromRequest(req);
        if (!active || !active.session) {
            return res.status(401).json({
                success: false,
                message: "No active authority session. Please log in."
            });
        }

        const isAuthority = active.session.actor_type === "AUTHORITY" || 
            ["warden", "attendant", "attendent", "chief-warden", "chiefwarden", "admin", "authority"].includes(String(active.session.role).toLowerCase());

        if (!isAuthority) {
            return res.status(403).json({
                success: false,
                conflict: true,
                currentRole: active.session.role || "student",
                message: `Active session belongs to '${active.session.role || "student"}'. Please log in through the Authority portal.`
            });
        }

        const authResult = await pool.query(
            "SELECT id, name, email, phone, hostel, status, approved_by FROM authority WHERE id = $1",
            [active.session.actor_id]
        );

        if (authResult.rows.length === 0) {
            return res.status(401).json({ success: false, message: "Authority user not found" });
        }

        const user = authResult.rows[0];
        const normalizedRole = user.status.toLowerCase().replace(/[\s_]+/g, "-");
        user.status = normalizedRole === "attendent" ? "attendant" : normalizedRole;
        user.role = user.status;

        // If access token was expired, silently reissue fresh access token
        if (active.needsRefresh) {
            const refreshTtl = getRefreshTokenExpiry(normalizedRole);
            const newAccessToken = generateAccessToken({
                id: user.id,
                email: user.email,
                role: normalizedRole,
                hostel: user.hostel,
                status: normalizedRole,
                sessionId: active.session.id
            });
            const cookieOpts = getCookieOptions(req, refreshTtl);
            res.cookie("token", newAccessToken, cookieOpts);
            res.cookie("accessToken", newAccessToken, cookieOpts);
        }

        return res.status(200).json({
            success: true,
            user,
            role: user.role,
            sessionId: active.session.id
        });
    } catch (err) {
        console.error("Authority me error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

module.exports = router;