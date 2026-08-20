const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { closeSession, deactivateUserSessions, findSessionById } = require('../utils/sessionService');
const { JWT_SECRET, getCookieOptions } = require('../utils/authHelpers');

router.post('/logout', async (req, res) => {
    try {
        let token = req.cookies?.accessToken || req.cookies?.token;
        const authHeader = req.headers.authorization || '';

        if (!token && authHeader.startsWith('Bearer ')) {
            token = authHeader.slice(7).trim();
        } else if (!token && req.headers.token) {
            token = req.headers.token;
        }

        let sessionId = req.body?.sessionId || req.headers['x-session-id'] || null;
        let actorId = null;
        let actorType = null;

        if (token) {
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                if (decoded.sessionId && !sessionId) {
                    sessionId = decoded.sessionId;
                }
                actorId = decoded.id;
                actorType = decoded.role;
            } catch (ignore) {
                // If token is expired, decode payload anyway to extract sessionId
                const decoded = jwt.decode(token);
                if (decoded) {
                    if (decoded.sessionId && !sessionId) {
                        sessionId = decoded.sessionId;
                    }
                    actorId = decoded.id;
                    actorType = decoded.role;
                }
            }
        }

        // Option to logout of all devices (requires authenticated token)
        if (req.body?.allDevices && actorId) {
            await deactivateUserSessions(actorId, actorType);
        } else if (sessionId) {
            await closeSession(sessionId);
        }

        // Clear cookies with matching options
        const cookieOpts = getCookieOptions(req);
        res.clearCookie('token', cookieOpts);
        res.clearCookie('accessToken', cookieOpts);
        res.clearCookie('refreshToken', cookieOpts);

        return res.status(200).json({
            success: true,
            message: 'Logged out successfully',
        });
    } catch (err) {
        console.error('Logout error:', err);
        return res.status(500).json({
            success: false,
            message: 'Internal server error during logout',
        });
    }
});

module.exports = router;
