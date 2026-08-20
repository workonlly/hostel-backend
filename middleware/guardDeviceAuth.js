const crypto = require("crypto");
const pool = require("../db/db");
const ApiError = require("../utils/apiError");
const asyncHandler = require("../utils/asyncHandler");

/**
 * Middleware to verify Guard Terminal Device Fingerprint & Token
 * Expects headers:
 *   - 'x-device-id': UUID/TEXT ID of the registered guard device
 *   - 'x-device-fingerprint': Browser hardware fingerprint hash
 *   - 'x-device-token': Cryptographic device secret token issued upon activation
 */
const verifyGuardDevice = asyncHandler(async (req, res, next) => {
    // Check headers, or fallback to body/query
    const deviceId = req.headers["x-device-id"] || req.body?.device_id || req.query?.device_id;
    const fingerprintHash = req.headers["x-device-fingerprint"] || req.body?.fingerprint_hash || req.query?.fingerprint_hash;
    const deviceToken = req.headers["x-device-token"] || req.body?.device_token || req.query?.device_token;

    const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "127.0.0.1";

    if (!deviceId) {
        throw new ApiError(401, "Device credentials missing. Please activate this device with Chief Warden.");
    }

    const result = await pool.query(
        "SELECT * FROM guard_devices WHERE id = $1",
        [deviceId]
    );

    if (result.rows.length === 0) {
        throw new ApiError(401, "Unrecognized device. Please register this terminal with the Chief Warden.");
    }

    const device = result.rows[0];

    // Check device status
    if (device.status === "REVOKED" || device.status === "BLOCKED") {
        await pool.query(
            "INSERT INTO guard_device_logs (id, device_id, event_type, ip_address, details) VALUES ($1, $2, 'REVOKED_ACCESS_ATTEMPT', $3, $4)",
            [crypto.randomUUID ? crypto.randomUUID() : require("crypto").randomUUID(), deviceId, clientIp, "Attempted access on revoked/blocked device"]
        );
        throw new ApiError(403, "This device has been deactivated/revoked by the Chief Warden.");
    }

    if (device.status === "PENDING_ACTIVATION") {
        throw new ApiError(403, "Device is not yet activated. Please complete activation using your pairing code.");
    }

    // Verify token using constant-time comparison
    let tokenMatches = false;
    if (deviceToken && device.device_token) {
        const bufA = Buffer.from(String(deviceToken));
        const bufB = Buffer.from(String(device.device_token));
        if (bufA.length === bufB.length) {
            tokenMatches = crypto.timingSafeEqual(bufA, bufB);
        }
    }

    if (!tokenMatches) {
        throw new ApiError(401, "Invalid device session. Please re-activate this terminal.");
    }

    // Verify Hardware Fingerprint Hash (with auto-sync when token is valid)
    if (device.fingerprint_hash && fingerprintHash && device.fingerprint_hash !== fingerprintHash) {
        // Log fingerprint variation for security audit without crashing guard operations
        const logId = crypto.randomUUID ? crypto.randomUUID() : require("crypto").randomUUID();
        pool.query(
            "INSERT INTO guard_device_logs (id, device_id, event_type, ip_address, details) VALUES ($1, $2, 'FINGERPRINT_VARIATION', $3, $4)",
            [logId, deviceId, clientIp, `Previous: ${device.fingerprint_hash.substring(0, 12)}..., Updated: ${fingerprintHash.substring(0, 12)}...`]
        ).catch(() => {});

        // Update stored fingerprint to latest stable hardware state
        pool.query(
            "UPDATE guard_devices SET fingerprint_hash = $1 WHERE id = $2",
            [fingerprintHash, deviceId]
        ).catch(() => {});
    }

    // Update last active timestamp & IP asynchronously
    pool.query(
        "UPDATE guard_devices SET last_active_at = CURRENT_TIMESTAMP, last_ip = $1 WHERE id = $2",
        [clientIp, deviceId]
    ).catch(err => console.error("Failed to update guard device activity:", err.message));

    // Attach verified device to req
    req.guardDevice = device;
    next();
});

module.exports = { verifyGuardDevice };
