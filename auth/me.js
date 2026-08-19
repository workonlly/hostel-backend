const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const pool = require('../db/db');
const { JWT_SECRET, getCookieOptions, generateAccessToken, getRefreshTokenExpiry, hashRefreshToken, generateRefreshToken, compareRefreshTokens } = require('../utils/authHelpers');
const { findSessionById, updateSessionRefresh } = require('../utils/sessionService');

/**
 * GET /api/auth/me
 *
 * Reads the HttpOnly access token cookie and returns the current user.
 * If the access token is expired but a valid refresh token cookie exists,
 * it silently rotates the tokens and returns the user — keeping the session alive
 * across browser restarts without ever exposing tokens to JavaScript.
 */
router.get('/me', async (req, res) => {
    try {
        const accessToken = req.cookies?.accessToken || req.cookies?.token;
        const refreshToken = req.cookies?.refreshToken;

        // ── Step 1: Try validating the access token ──────────────────────────
        if (accessToken) {
            try {
                const decoded = jwt.verify(accessToken, JWT_SECRET);

                // Validate session is still active in DB
                if (decoded.sessionId) {
                    const session = await findSessionById(decoded.sessionId);
                    if (!session || !session.is_active) {
                        return res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
                    }
                }

                // Fetch fresh user data
                const user = await fetchUser(decoded.id, decoded.role);
                if (!user) {
                    return res.status(401).json({ success: false, message: 'User not found.' });
                }

                return res.status(200).json({ success: true, user });
            } catch (err) {
                // Access token invalid or expired — fall through to refresh flow
                if (err.name !== 'TokenExpiredError') {
                    return res.status(401).json({ success: false, message: 'Invalid token.' });
                }
            }
        }

        // ── Step 2: Access token expired — try refresh token ─────────────────
        if (!refreshToken) {
            return res.status(401).json({ success: false, message: 'Not authenticated.' });
        }

        // Decode the expired access token (without verification) to get sessionId
        let expiredDecoded = null;
        if (accessToken) {
            try {
                expiredDecoded = jwt.decode(accessToken);
            } catch (_) { /* ignore */ }
        }

        const sessionId = expiredDecoded?.sessionId || req.headers['x-session-id'];
        if (!sessionId) {
            return res.status(401).json({ success: false, message: 'Session not found. Please log in again.' });
        }

        const session = await findSessionById(sessionId);
        if (!session || !session.is_active) {
            return res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
        }

        if (session.refresh_expires_at && new Date() > new Date(session.refresh_expires_at)) {
            return res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
        }

        const isMatch = await compareRefreshTokens(refreshToken, session.refresh_token_hash);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid refresh token. Please log in again.' });
        }

        // Rotate refresh token
        const newRefreshToken = generateRefreshToken();
        const newRefreshTokenHash = await hashRefreshToken(newRefreshToken);
        const newRefreshExpiresAt = new Date(Date.now() + getRefreshTokenExpiry(session.role));

        await updateSessionRefresh(session.id, {
            refreshTokenHash: newRefreshTokenHash,
            refreshExpiresAt: newRefreshExpiresAt,
            isActive: true,
        });

        // Fetch fresh user data
        const user = await fetchUser(session.actor_id, session.role);
        if (!user) {
            return res.status(401).json({ success: false, message: 'User not found.' });
        }

        // Generate new access token payload
        const tokenPayload = {
            id: session.actor_id,
            email: user.email,
            role: session.role,
            hostel: user.hostel,
            sessionId: session.id,
        };

        const newAccessToken = generateAccessToken(tokenPayload);

        // Set rotated HttpOnly cookies silently
        const cookieOpts = getCookieOptions(req);
        res.cookie('token', newAccessToken, cookieOpts);
        res.cookie('accessToken', newAccessToken, cookieOpts);
        res.cookie('refreshToken', newRefreshToken, cookieOpts);

        return res.status(200).json({ success: true, user });

    } catch (err) {
        console.error('GET /me error:', err);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});

/**
 * Fetch user profile based on ID and role.
 * Returns a sanitized user object (no password).
 */
async function fetchUser(id, role) {
    try {
        const normalizedRole = String(role || '').toLowerCase();

        if (normalizedRole === 'student') {
            const result = await pool.query(
                `SELECT s.*, r.room_number AS room_number
                 FROM students s
                 LEFT JOIN room r ON r.id = s.physical_room_id
                 WHERE s.id = $1`,
                [id]
            );
            if (result.rows.length === 0) return null;
            const user = result.rows[0];
            delete user.password;
            user.role = 'student';
            user.physical_room_id = user.room_number || user.physical_room_id;
            delete user.room_number;
            return user;
        } else {
            // Authority (warden, chief-warden, attendant, guard)
            const result = await pool.query(
                `SELECT id, name, email, status, hostel FROM authority WHERE id = $1`,
                [id]
            );
            if (result.rows.length === 0) return null;
            const user = result.rows[0];
            user.role = user.status || role;
            return user;
        }
    } catch (err) {
        console.error('fetchUser error:', err);
        return null;
    }
}

module.exports = router;
