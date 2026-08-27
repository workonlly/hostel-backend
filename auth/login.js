const express = require('express');
const router = express.Router();
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const pool = require("../db/db");
const { generateOtp, sendOtpEmail } = require("./otp");
const { authLimiter, otpVerifyLimiter } = require("../middleware/rateLimiter");
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
        const { email, password, role, forceLogout } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "Email and password are required" });
        }
        const normalizedEmail = String(email || "").trim().toLowerCase();

        // 1. Check for conflicting active sessions (e.g., student attempting login while admin is active)
        const conflict = await checkSessionConflict(req, "student", null, { forceLogout: Boolean(forceLogout) });
        if (conflict.hasConflict) {
            return res.status(409).json({
                success: false,
                conflict: true,
                currentRole: conflict.currentRole,
                message: conflict.message
            });
        }

        // Note: Currently only supporting "student" role logic.
        const userCheck = await pool.query(
            `SELECT s.*, r.room_number AS room_number
             FROM students s
             LEFT JOIN room r ON r.id = s.physical_room_id
             WHERE s.email = $1`,
            [normalizedEmail]
        );
        if (userCheck.rows.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        const user = userCheck.rows[0];

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        // Generate and send OTP
        const otp = generateOtp();
        await sendOtpEmail(normalizedEmail, otp);

        const expiresAt = new Date(Date.now() + 5 * 60000);
        const otpId = crypto.randomUUID();
        const hashedOtp = crypto.createHash("sha256").update(String(otp).trim()).digest("hex");
        
        await pool.query(
            "INSERT INTO otp_verification (id, person_id, otp, expires_at) VALUES ($1, $2, $3, $4)",
            [otpId, normalizedEmail, hashedOtp, expiresAt]
        );

        return res.status(200).json({ success: true, message: "OTP generated" });
    } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

router.post("/verify-login-otp", otpVerifyLimiter, async (req, res) => {
    try {
        const { email, otp, role, forceLogout } = req.body;
        const normalizedEmail = String(email || "").trim().toLowerCase();

        // ===================== TESTING MODE =====================
        // When otp is the master test code, skip real verification.
        // TODO: Remove this bypass before going to production.
        const TESTING_OTP = "123456";
        const isBypassOtp = String(otp).trim() === TESTING_OTP;

        let otpRecord = null;

        if (!isBypassOtp) {
            // -- REAL OTP VERIFICATION (commented out for testing) --
            const hashedOtp = crypto.createHash("sha256").update(String(otp).trim()).digest("hex");

            const otpCheck = await pool.query(
                "SELECT id, expires_at FROM otp_verification WHERE person_id = $1 AND otp = $2 ORDER BY created_at DESC LIMIT 1",
                [normalizedEmail, hashedOtp]
            );

            if (otpCheck.rows.length === 0) {
                return res.status(400).json({ success: false, message: "Invalid OTP" });
            }

            otpRecord = otpCheck.rows[0];
            if (new Date() > new Date(otpRecord.expires_at)) {
                return res.status(400).json({ success: false, message: "OTP has expired" });
            }
        } else {
            console.log(`[TESTING MODE] Bypass OTP used for: ${normalizedEmail}`);
        }
        // =========================================================

        // Fetch user data for payload
        const userCheck = await pool.query(
            `SELECT s.*, r.room_number AS room_number
             FROM students s
             LEFT JOIN room r ON r.id = s.physical_room_id
             WHERE s.email = $1`,
            [normalizedEmail]
        );

        if (userCheck.rows.length === 0) {
            return res.status(401).json({ success: false, message: "Student account not found" });
        }

        const user = userCheck.rows[0];

        // Check for session conflict before issuing tokens
        const conflict = await checkSessionConflict(req, "student", user.id, { forceLogout: Boolean(forceLogout) });
        if (conflict.hasConflict) {
            return res.status(409).json({
                success: false,
                conflict: true,
                currentRole: conflict.currentRole,
                message: conflict.message
            });
        }

        // Deactivate older active sessions for this student on fresh login
        await deactivateUserSessions(user.id, "STUDENT");

        // 1. Prepare session details
        const refreshTtl = getRefreshTokenExpiry("student");
        const refreshToken = generateRefreshToken();
        const refreshTokenHash = await hashRefreshToken(refreshToken);
        const refreshExpiresAt = new Date(Date.now() + refreshTtl);
        const ipAddress = getClientIp(req);
        const userAgent = req.headers["user-agent"] || null;

        // 2. Create user_session in DB
        const session = await createSession({
            actorId: user.id,
            actorType: "STUDENT",
            ipAddress,
            userAgent,
            role: "student",
            refreshTokenHash,
            refreshExpiresAt,
            machineId: req.body.machineId || null
        });

        // 3. Generate short-lived Access Token containing sessionId
        const accessToken = generateAccessToken({
            id: user.id,
            email: user.email,
            role: "student",
            hostel: user.hostel,
            sessionId: session.id
        });

        // Remove sensitive fields
        delete user.password;
        user.physical_room_id = user.room_number || user.physical_room_id;
        delete user.room_number;
        user.role = "student";

        // Cleanup OTP record (skipped in testing bypass mode)
        if (otpRecord) {
            await pool.query("DELETE FROM otp_verification WHERE id = $1", [otpRecord.id]);
        }

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
        console.error("OTP verify error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

/**
 * GET /api/auth/me - Validates existing student session and auto-refreshes token if needed
 */
router.get("/me", async (req, res) => {
    try {
        const active = await getActiveSessionFromRequest(req);
        if (!active || !active.session) {
            return res.status(401).json({
                success: false,
                message: "No active session. Please log in."
            });
        }

        const isStudent = active.session.actor_type === "STUDENT" || active.session.role === "student";
        if (!isStudent) {
            return res.status(403).json({
                success: false,
                conflict: true,
                currentRole: active.session.role || "authority",
                message: `Active session belongs to '${active.session.role || "authority"}'. Please log in through the appropriate portal.`
            });
        }

        const userResult = await pool.query(
            `SELECT s.*, r.room_number AS room_number
             FROM students s
             LEFT JOIN room r ON r.id = s.physical_room_id
             WHERE s.id = $1`,
            [active.session.actor_id]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ success: false, message: "Student record not found" });
        }

        const user = userResult.rows[0];
        delete user.password;
        user.physical_room_id = user.room_number || user.physical_room_id;
        delete user.room_number;
        user.role = "student";

        // If access token was expired, silently reissue fresh access token
        if (active.needsRefresh) {
            const refreshTtl = getRefreshTokenExpiry("student");
            const newAccessToken = generateAccessToken({
                id: user.id,
                email: user.email,
                role: "student",
                hostel: user.hostel,
                sessionId: active.session.id
            });
            const cookieOpts = getCookieOptions(req, refreshTtl);
            res.cookie("token", newAccessToken, cookieOpts);
            res.cookie("accessToken", newAccessToken, cookieOpts);
        }

        return res.status(200).json({
            success: true,
            user,
            role: "student",
            sessionId: active.session.id
        });
    } catch (err) {
        console.error("Auth me error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

module.exports = router;

