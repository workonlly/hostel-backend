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
const { createSession } = require("../utils/sessionService");

router.post("/login", authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

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

        // 1. Prepare session details
        const refreshToken = generateRefreshToken();
        const refreshTokenHash = await hashRefreshToken(refreshToken);
        const refreshExpiresAt = new Date(Date.now() + getRefreshTokenExpiry(normalizedRole));
        const ipAddress = getClientIp(req);
        const userAgent = req.headers["user-agent"] || null;

        // 2. Create user_session in DB
        const session = await createSession({
            actorId: user.id,
            actorType: normalizedRole === 'guard' ? 'GUARD' : 'AUTHORITY',
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

        // Set pure HttpOnly cookies (SameSite=none for cross-domain Render deployments)
        const cookieOpts = getCookieOptions(req);
        res.cookie("token", accessToken, cookieOpts);
        res.cookie("accessToken", accessToken, cookieOpts);
        res.cookie("refreshToken", refreshToken, cookieOpts);

        // Tokens are set as HttpOnly cookies above — never expose them in the JSON body
        return res.status(200).json({
            success: true,
            user
        });
    } catch (err) {
        console.error("Authority login error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

module.exports = router;