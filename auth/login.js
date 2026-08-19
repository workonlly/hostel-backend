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
const { createSession } = require("../utils/sessionService");

router.post("/login", authLimiter, async (req, res) => {
    try {
        const { email, password, role } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "Email and password are required" });
        }
        const normalizedEmail = String(email || "").trim().toLowerCase();

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
        const { email, otp, role } = req.body;
        const normalizedEmail = String(email || "").trim().toLowerCase();
        const hashedOtp = crypto.createHash("sha256").update(String(otp).trim()).digest("hex");

        const otpCheck = await pool.query(
            "SELECT id, expires_at FROM otp_verification WHERE person_id = $1 AND otp = $2 ORDER BY created_at DESC LIMIT 1",
            [normalizedEmail, hashedOtp]
        );

        if (otpCheck.rows.length === 0) {
            return res.status(400).json({ success: false, message: "Invalid OTP" });
        }

        const otpRecord = otpCheck.rows[0];
        if (new Date() > new Date(otpRecord.expires_at)) {
            return res.status(400).json({ success: false, message: "OTP has expired" });
        }

        // Fetch user data for payload
        const userCheck = await pool.query(
            `SELECT s.*, r.room_number AS room_number
             FROM students s
             LEFT JOIN room r ON r.id = s.physical_room_id
             WHERE s.email = $1`,
            [email]
        );
        const user = userCheck.rows[0];

        // 1. Prepare session details
        const refreshToken = generateRefreshToken();
        const refreshTokenHash = await hashRefreshToken(refreshToken);
        const refreshExpiresAt = new Date(Date.now() + getRefreshTokenExpiry("student"));
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

        // Cleanup OTP record
        await pool.query("DELETE FROM otp_verification WHERE id = $1", [otpRecord.id]);

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
        console.error("OTP verify error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

module.exports = router;
