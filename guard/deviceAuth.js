const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const pool = require("../db/db");
const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/apiError");
const ApiResponse = require("../utils/apiResponse");

const { authLimiter } = require("../middleware/rateLimiter");

/**
 * ACTIVATE GUARD DEVICE
 * POST /api/guard/device/activate
 * Guard inputs phone number & activation code provided by Chief Warden.
 * App provides hardware fingerprint hash and browser details.
 */
router.post(
    "/activate",
    authLimiter,
    asyncHandler(async (req, res) => {
        const { phone, activation_code, fingerprint_hash, device_info } = req.body;
        const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "127.0.0.1";

        if (!phone || !activation_code) {
            throw new ApiError(400, "Phone number and Activation Code are required");
        }

        if (!fingerprint_hash) {
            throw new ApiError(400, "Device fingerprint could not be computed. Please enable JavaScript and WebGL.");
        }

        // Clean up input
        const cleanPhone = phone.trim();
        const cleanCode = activation_code.trim().toUpperCase();

        const result = await pool.query(
            "SELECT * FROM guard_devices WHERE phone = $1",
            [cleanPhone]
        );

        if (result.rows.length === 0) {
            throw new ApiError(404, "No guard terminal found for this phone number. Please contact Chief Warden.");
        }

        const device = result.rows[0];

        // Check if device is blocked
        if (device.status === "REVOKED" || device.status === "BLOCKED") {
            throw new ApiError(403, "This guard slot has been disabled by the Chief Warden.");
        }

        // Validate Activation Code using timingSafeEqual
        let codeMatches = false;
        if (device.activation_code) {
            const bufA = Buffer.from(device.activation_code.toUpperCase());
            const bufB = Buffer.from(cleanCode);
            if (bufA.length === bufB.length) {
                codeMatches = crypto.timingSafeEqual(bufA, bufB);
            }
        }

        if (!codeMatches) {
            const logId = crypto.randomUUID();
            await pool.query(
                "INSERT INTO guard_device_logs (id, device_id, event_type, ip_address, details) VALUES ($1, $2, 'INVALID_ACTIVATION_CODE', $3, $4)",
                [logId, device.id, clientIp, `Provided code: ${cleanCode}`]
            );
            throw new ApiError(401, "Invalid Activation Code. Please check the code provided by Chief Warden.");
        }

        // Check if already bound to another fingerprint (and not reset)
        if (device.fingerprint_hash && device.fingerprint_hash !== fingerprint_hash && device.status === "ACTIVE") {
            const logId = crypto.randomUUID();
            await pool.query(
                "INSERT INTO guard_device_logs (id, device_id, event_type, ip_address, details) VALUES ($1, $2, 'HARDWARE_ALREADY_BOUND', $3, $4)",
                [logId, device.id, clientIp, `Attempted re-binding without reset from Chief Warden`]
            );
            throw new ApiError(409, "This terminal is already bound to another physical device. Ask Chief Warden to reset the device binding.");
        }

        // Generate a new secure device token
        const deviceToken = "gdt_" + crypto.randomBytes(32).toString("hex");

        // Bind device hardware fingerprint and set status to ACTIVE
        await pool.query(
            `UPDATE guard_devices 
             SET fingerprint_hash = $1,
                 device_info = $2,
                 device_token = $3,
                 status = 'ACTIVE',
                 last_active_at = CURRENT_TIMESTAMP,
                 last_ip = $4,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $5`,
            [fingerprint_hash, JSON.stringify(device_info || {}), deviceToken, clientIp, device.id]
        );

        // Log activation success
        const logId = crypto.randomUUID();
        await pool.query(
            "INSERT INTO guard_device_logs (id, device_id, event_type, ip_address, details) VALUES ($1, $2, 'DEVICE_ACTIVATED', $3, $4)",
            [logId, device.id, clientIp, `Device activated with fingerprint ${fingerprint_hash.substring(0, 10)}...`]
        );

        // Re-fetch to get updated guard_type / hostel_id (set by Chief Warden at creation)
        const updatedDevice = await pool.query(
            "SELECT id, device_name, phone, gate, guard_type, hostel_id FROM guard_devices WHERE id = $1",
            [device.id]
        );
        const dev = updatedDevice.rows[0];

        // Resolve hostel name for the frontend sidebar label
        let hostelName = null;
        if (dev.hostel_id) {
            const hostelRes = await pool.query("SELECT name FROM hostel WHERE id = $1", [dev.hostel_id]);
            hostelName = hostelRes.rows[0]?.name || null;
        }

        return res.status(200).json(
            new ApiResponse(
                200,
                {
                    device_id: dev.id,
                    device_name: dev.device_name,
                    gate: dev.gate,
                    phone: dev.phone,
                    status: "ACTIVE",
                    device_token: deviceToken,
                    guard_type: dev.guard_type || "MAIN_GATE",
                    hostel_id: dev.hostel_id || null,
                    hostel_name: hostelName
                },
                "Guard Terminal successfully bound and activated!"
            )
        );
    })
);

/**
 * VERIFY DEVICE
 * POST /api/guard/device/verify
 * Checks if current device credentials & fingerprint are valid
 */
router.post(
    "/verify",
    asyncHandler(async (req, res) => {
        const { device_id, fingerprint_hash, device_token } = req.body;
        const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "127.0.0.1";

        if (!device_id) {
            throw new ApiError(400, "Device ID is required");
        }

        const result = await pool.query(
            "SELECT id, device_name, phone, gate, fingerprint_hash, device_token, status, last_active_at, guard_type, hostel_id FROM guard_devices WHERE id = $1",
            [device_id]
        );

        if (result.rows.length === 0) {
            return res.status(200).json(
                new ApiResponse(200, { isValid: false, reason: "DEVICE_NOT_FOUND", message: "Device registration not found" })
            );
        }

        const device = result.rows[0];

        if (device.status === "REVOKED" || device.status === "BLOCKED") {
            return res.status(200).json(
                new ApiResponse(200, { isValid: false, status: device.status, reason: "DEVICE_REVOKED", message: "Device access has been revoked by Chief Warden." })
            );
        }

        if (device.status === "PENDING_ACTIVATION") {
            return res.status(200).json(
                new ApiResponse(200, { isValid: false, status: device.status, reason: "PENDING_ACTIVATION", message: "Device requires activation." })
            );
        }

        let tokenMatches = false;
        if (device.device_token && device_token) {
            const bufA = Buffer.from(String(device.device_token));
            const bufB = Buffer.from(String(device_token));
            if (bufA.length === bufB.length) {
                tokenMatches = crypto.timingSafeEqual(bufA, bufB);
            }
        }

        if (device.device_token && !tokenMatches) {
            return res.status(200).json(
                new ApiResponse(200, { isValid: false, reason: "TOKEN_MISMATCH", message: "Invalid session token. Please re-activate." })
            );
        }

        if (device.fingerprint_hash && fingerprint_hash && device.fingerprint_hash !== fingerprint_hash) {
            const logId = crypto.randomUUID();
            pool.query(
                "INSERT INTO guard_device_logs (id, device_id, event_type, ip_address, details) VALUES ($1, $2, 'FINGERPRINT_AUTO_SYNC', $3, $4)",
                [logId, device.id, clientIp, `Auto-synced fingerprint: ${fingerprint_hash.substring(0, 12)}...`]
            ).catch(() => {});

            // Auto-update to latest hardware state
            pool.query(
                "UPDATE guard_devices SET fingerprint_hash = $1 WHERE id = $2",
                [fingerprint_hash, device.id]
            ).catch(() => {});
        }

        // Update active status
        pool.query(
            "UPDATE guard_devices SET last_active_at = CURRENT_TIMESTAMP, last_ip = $1 WHERE id = $2",
            [clientIp, device.id]
        ).catch(err => console.error("Update activity failed:", err.message));

        // Resolve hostel name if bound to a hostel
        let hostelName = null;
        if (device.hostel_id) {
            const hostelRes = await pool.query("SELECT name FROM hostel WHERE id = $1", [device.hostel_id]);
            hostelName = hostelRes.rows[0]?.name || null;
        }

        return res.status(200).json(
            new ApiResponse(
                200,
                {
                    isValid: true,
                    device_id: device.id,
                    device_name: device.device_name,
                    gate: device.gate,
                    phone: device.phone,
                    status: device.status,
                    guard_type: device.guard_type || "MAIN_GATE",
                    hostel_id: device.hostel_id || null,
                    hostel_name: hostelName
                },
                "Device verified successfully"
            )
        );
    })
);

module.exports = router;
