const express = require('express');
const router = express.Router();
const pool = require('../db/db');
const {
    getRefreshTokenExpiry,
    hashRefreshToken,
    compareRefreshTokens,
    generateRefreshToken,
    generateAccessToken,
    getCookieOptions,
} = require('../utils/authHelpers');
const { authLimiter } = require('../middleware/rateLimiter');
const { findSessionById, updateSessionRefresh } = require('../utils/sessionService');

router.post('/refresh', authLimiter, async (req, res) => {
    try {
        const refreshToken = req.body.refreshToken || req.cookies?.refreshToken;
        const sessionId = req.body.sessionId || req.headers['x-session-id'] || req.headers.sessionid;

        if (!refreshToken || !sessionId) {
            return res.status(400).json({
                success: false,
                message: 'Refresh token and sessionId are required',
            });
        }

        const session = await findSessionById(sessionId);

        if (!session || !session.is_active) {
            return res.status(401).json({
                success: false,
                message: 'Session is inactive or does not exist. Please log in again.',
            });
        }

        if (session.refresh_expires_at && new Date() > new Date(session.refresh_expires_at)) {
            return res.status(401).json({
                success: false,
                message: 'Refresh token has expired. Please log in again.',
            });
        }

        // Verify hash if sessionId was directly supplied
        if (sessionId) {
            const isMatch = await compareRefreshTokens(refreshToken, session.refresh_token_hash);
            if (!isMatch) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid refresh token. Please log in again.',
                });
            }
        }

        // Retrieve user details for token payload
        let userPayload = {
            id: session.actor_id,
            role: session.role,
            sessionId: session.id,
        };

        if (session.actor_type === 'STUDENT') {
            const stu = await pool.query('SELECT email, hostel FROM students WHERE id = $1', [session.actor_id]);
            if (stu.rows.length > 0) {
                userPayload.email = stu.rows[0].email;
                userPayload.hostel = stu.rows[0].hostel;
            }
        } else {
            const auth = await pool.query('SELECT email, hostel FROM authority WHERE id = $1', [session.actor_id]);
            if (auth.rows.length > 0) {
                userPayload.email = auth.rows[0].email;
                userPayload.hostel = auth.rows[0].hostel;
                userPayload.status = session.role;
            }
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

        // Generate new Access Token
        const newAccessToken = generateAccessToken(userPayload);

        // Set pure HttpOnly cookies (SameSite=none for cross-domain Render deployments)
        const cookieOpts = getCookieOptions(req);
        res.cookie('token', newAccessToken, cookieOpts);
        res.cookie('accessToken', newAccessToken, cookieOpts);
        res.cookie('refreshToken', newRefreshToken, cookieOpts);

        // Tokens are set as HttpOnly cookies above — never expose them in the JSON body
        return res.status(200).json({
            success: true,
        });
    } catch (err) {
        console.error('Refresh token error:', err);
        return res.status(500).json({
            success: false,
            message: 'Internal server error during token refresh',
        });
    }
});

module.exports = router;
