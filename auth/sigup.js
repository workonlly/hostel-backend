const express = require('express');
const router = express.Router();
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const pool = require("../db/db");
const { findOrCreateHostel, findOrCreateRoom } = require("../db/hostel");
const { generateOtp, sendOtpEmail } = require("./otp");
const { otpLimiter, otpVerifyLimiter, authLimiter } = require("../middleware/rateLimiter");
const {
    getClientIp,
    getRefreshTokenExpiry,
    hashRefreshToken,
    generateRefreshToken,
    generateAccessToken,
    getCookieOptions
} = require("../utils/authHelpers");
const { createSession, checkSessionConflict, deactivateUserSessions } = require("../utils/sessionService");

const COLLEGE_EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@nith\.ac\.in$/;

function hashOtp(otp) {
    return crypto.createHash("sha256").update(String(otp).trim()).digest("hex");
}

// 1. /send-otp
router.post("/send-otp", otpLimiter, async (req, res) => {
    try {
        const { email, forceLogout } = req.body;
        const normalizedEmail = String(email || "").trim().toLowerCase();
        
        // Strict email domain validation
        if (!normalizedEmail || !COLLEGE_EMAIL_REGEX.test(normalizedEmail)) {
            return res.status(400).json({ success: false, message: "Invalid college email. Must be a valid @nith.ac.in address." });
        }

        // Check for conflicting active sessions (e.g. authority active)
        const conflict = await checkSessionConflict(req, "student", null, { forceLogout: Boolean(forceLogout) });
        if (conflict.hasConflict) {
            return res.status(409).json({
                success: false,
                conflict: true,
                currentRole: conflict.currentRole,
                message: conflict.message
            });
        }

        // Check if user already exists
        const userCheck = await pool.query("SELECT id FROM students WHERE email = $1", [normalizedEmail]);
        if (userCheck.rows.length > 0) {
            return res.status(409).json({ success: false, message: "Account already exists. Please login." });
        }

        // Generate and send OTP
        const otp = generateOtp();
        await sendOtpEmail(normalizedEmail, otp);

        // Store hashed OTP in database
        const expiresAt = new Date(Date.now() + 5 * 60000); // 5 mins from now
        const otpId = crypto.randomUUID();
        const hashedOtp = hashOtp(otp);
        
        await pool.query(
            "INSERT INTO otp_verification (id, person_id, otp, expires_at) VALUES ($1, $2, $3, $4)",
            [otpId, normalizedEmail, hashedOtp, expiresAt]
        );

        return res.status(200).json({ success: true, message: "OTP sent successfully" });
    } catch (err) {
        console.error("OTP generation error:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error while sending OTP" });
    }
});

// 2. /verify-signup-otp
router.post("/verify-signup-otp", otpVerifyLimiter, async (req, res) => {
    try {
        const { email, otp } = req.body;
        const normalizedEmail = String(email || "").trim().toLowerCase();

        // ===================== TESTING MODE =====================
        // When otp is the master test code, skip real verification.
        // TODO: Remove this bypass before going to production.
        const TESTING_OTP = "123456";
        const isBypassOtp = String(otp).trim() === TESTING_OTP;

        if (!isBypassOtp) {
            // -- REAL OTP VERIFICATION (commented out for testing) --
            const hashedOtp = hashOtp(otp);

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

            // Mark as verified
            await pool.query(
                "UPDATE otp_verification SET is_verified = true WHERE id = $1",
                [otpRecord.id]
            );
        } else {
            console.log(`[TESTING MODE] Bypass OTP used for signup: ${normalizedEmail}`);
        }
        // =========================================================

        return res.status(200).json({ success: true, message: "OTP verified" });
    } catch (err) {
        console.error("OTP verification error:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error during OTP verification" });
    }
});

// 3. /signup
router.post("/signup", authLimiter, async (req, res) => {
    try {
        const { name, email, password, phone, hostel, room, department, rollno, degree_type, academic_year, forceLogout } = req.body;
        const normalizedEmail = String(email || "").trim().toLowerCase();

        if (!normalizedEmail || !COLLEGE_EMAIL_REGEX.test(normalizedEmail)) {
            return res.status(400).json({ success: false, message: "Invalid college email. Must be a valid @nith.ac.in address." });
        }

        // Check for session conflicts
        const conflict = await checkSessionConflict(req, "student", null, { forceLogout: Boolean(forceLogout) });
        if (conflict.hasConflict) {
            return res.status(409).json({
                success: false,
                conflict: true,
                currentRole: conflict.currentRole,
                message: conflict.message
            });
        }

        // Verify that email was recently verified (within last 15 mins)
        // ===================== TESTING MODE =====================
        // TODO: Remove TESTING_MODE bypass before going to production.
        const TESTING_MODE = process.env.TESTING_MODE === "true";
        if (!TESTING_MODE) {
            const verifyCheck = await pool.query(
                "SELECT id, is_verified, created_at FROM otp_verification WHERE person_id = $1 AND is_verified = true AND created_at >= NOW() - INTERVAL '15 minutes' ORDER BY created_at DESC LIMIT 1",
                [normalizedEmail]
            );

            if (verifyCheck.rows.length === 0 || !verifyCheck.rows[0].is_verified) {
                return res.status(403).json({ success: false, message: "Email not verified or verification session expired" });
            }
        } else {
            console.log(`[TESTING MODE] Skipping email verification check for: ${normalizedEmail}`);
        }
        // =========================================================

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        const studentId = crypto.randomUUID();

        const client = await pool.connect();
        try {
            await client.query("BEGIN");

            const hostelRecord = await findOrCreateHostel(client, { name: hostel });
            if (!hostelRecord) {
                await client.query("ROLLBACK");
                return res.status(400).json({ success: false, message: "A valid hostel is required" });
            }

            const roomRecord = await findOrCreateRoom(client, {
                hostelId: hostelRecord.id,
                roomNumber: room,
            });
            if (!roomRecord) {
                await client.query("ROLLBACK");
                return res.status(400).json({ success: false, message: "A valid room number is required" });
            }

            await client.query(
                `INSERT INTO students
                (id, name, email, password, phone, hostel, hostel_id, physical_room_id, department, roll_no, degree_type, academic_year)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
                [studentId, name, normalizedEmail, hashedPassword, phone, hostelRecord.name, hostelRecord.id, roomRecord.id, department, rollno, degree_type, academic_year]
            );

            // Clean up and consume verified OTPs
            await client.query("DELETE FROM otp_verification WHERE person_id = $1", [normalizedEmail]);

            await client.query("COMMIT");
            
            // Deactivate any existing active sessions
            await deactivateUserSessions(studentId, "STUDENT");

            // Generate Session & Tokens for Auto-Login
            const refreshTtl = getRefreshTokenExpiry("student");
            const refreshToken = generateRefreshToken();
            const refreshTokenHash = await hashRefreshToken(refreshToken);
            const refreshExpiresAt = new Date(Date.now() + refreshTtl);
            const ipAddress = getClientIp(req);
            const userAgent = req.headers["user-agent"] || null;

            const session = await createSession({
                actorId: studentId,
                actorType: "STUDENT",
                ipAddress,
                userAgent,
                role: "student",
                refreshTokenHash,
                refreshExpiresAt,
                machineId: req.body.machineId || null
            });

            const accessToken = generateAccessToken({
                id: studentId,
                email: email,
                role: "student",
                hostel: hostelRecord.name,
                sessionId: session.id
            });
            
            // Build the complete user object to return to the frontend
            const fullUser = {
                id: studentId,
                name,
                email,
                phone,
                hostel: hostelRecord.name,
                physical_room_id: roomRecord.room_number,
                department,
                roll_no: rollno,
                degree_type,
                academic_year,
                role: "student",
                father_name: null,
                category: null,
                blood_group: null,
                state: null
            };

            // Set persistent HttpOnly cookies
            const cookieOpts = getCookieOptions(req, refreshTtl);
            res.cookie("token", accessToken, cookieOpts);
            res.cookie("accessToken", accessToken, cookieOpts);
            res.cookie("refreshToken", refreshToken, cookieOpts);

            return res.status(201).json({ 
                success: true, 
                message: "Signup successful. Logged in.",
                sessionId: session.id,
                token: accessToken,
                accessToken: accessToken,
                refreshToken: refreshToken,
                user: fullUser
            });
        } catch (error) {
            await client.query("ROLLBACK");
            throw error;
        } finally {
            client.release();
        }
    } catch (err) {
        console.error("Signup error:", err);
        // Handle unique constraint errors (e.g. roll_no already exists)
        if (err.code === '23505') {
             return res.status(400).json({ success: false, message: "Roll number or email already in use." });
        }
        return res.status(500).json({ success: false, message: "Internal Server Error during signup" });
    }
});

module.exports = router;
