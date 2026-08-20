const pool = require('../db/db');

/**
 * Normalizes actor type (STUDENT, AUTHORITY, GUARD, etc.)
 */
function normalizeActorType(roleOrType) {
    if (!roleOrType) return 'STUDENT';
    const lower = String(roleOrType).trim().toLowerCase();
    if (lower === 'guard') return 'GUARD';
    if (lower === 'student') return 'STUDENT';
    if (['warden', 'attendant', 'attendent', 'chief-warden', 'chiefwarden', 'admin', 'authority'].includes(lower)) {
        return 'AUTHORITY';
    }
    return lower.toUpperCase();
}

/**
 * Create a new user session entry in the database.
 */
async function createSession({
    actorId,
    actorType,
    ipAddress = null,
    userAgent = null,
    role = null,
    refreshTokenHash = null,
    refreshExpiresAt = null,
    isActive = true,
    machineId = null,
}) {
    const normActorType = normalizeActorType(actorType || role);
    const query = `
        INSERT INTO user_session (
            actor_id,
            actor_type,
            ip_address,
            user_agent,
            role,
            refresh_token_hash,
            refresh_expires_at,
            is_active,
            machine_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *;
    `;
    const values = [
        String(actorId),
        normActorType,
        ipAddress,
        userAgent,
        role,
        refreshTokenHash,
        refreshExpiresAt,
        Boolean(isActive),
        machineId,
    ];
    const result = await pool.query(query, values);
    return result.rows[0];
}

/**
 * Find a session by its UUID.
 */
async function findSessionById(sessionId) {
    if (!sessionId) return null;
    const query = `
        SELECT * FROM user_session
        WHERE id = $1
        LIMIT 1;
    `;
    const result = await pool.query(query, [sessionId]);
    return result.rows[0] || null;
}

/**
 * Find active session for an actor.
 */
async function findActiveSession({ actorId, actorType }) {
    if (!actorId) return null;
    const normActorType = normalizeActorType(actorType);
    const query = `
        SELECT * FROM user_session
        WHERE actor_id = $1 AND actor_type = $2 AND is_active = TRUE
        ORDER BY login_time DESC
        LIMIT 1;
    `;
    const result = await pool.query(query, [String(actorId), normActorType]);
    return result.rows[0] || null;
}

/**
 * Close/deactivate a single session.
 */
async function closeSession(sessionId, logoutTime = new Date()) {
    if (!sessionId) return null;
    const query = `
        UPDATE user_session
        SET logout_time = $1,
            is_active = FALSE,
            refresh_token_hash = NULL
        WHERE id = $2
        RETURNING *;
    `;
    const result = await pool.query(query, [logoutTime, sessionId]);
    return result.rows[0] || null;
}

/**
 * Deactivate all active sessions for an actor (e.g. on password reset or remote logout).
 */
async function deactivateUserSessions(actorId, actorType, logoutTime = new Date()) {
    if (!actorId) return [];
    const normActorType = normalizeActorType(actorType);
    const query = `
        UPDATE user_session
        SET logout_time = $1,
            is_active = FALSE,
            refresh_token_hash = NULL
        WHERE actor_id = $2 AND actor_type = $3 AND is_active = TRUE
        RETURNING *;
    `;
    const result = await pool.query(query, [logoutTime, String(actorId), normActorType]);
    return result.rows;
}

/**
 * Update session refresh token upon rotation.
 */
async function updateSessionRefresh(sessionId, { refreshTokenHash, refreshExpiresAt, isActive = true }) {
    if (!sessionId) return null;
    const query = `
        UPDATE user_session
        SET refresh_token_hash = $1,
            refresh_expires_at = $2,
            is_active = $3
        WHERE id = $4
        RETURNING *;
    `;
    const values = [refreshTokenHash, refreshExpiresAt, Boolean(isActive), sessionId];
    const result = await pool.query(query, values);
    return result.rows[0] || null;
}

const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

/**
 * Inspects incoming request to retrieve currently active session (from token, cookie, or header)
 */
async function getActiveSessionFromRequest(req) {
    if (!req) return null;
    let token = req.cookies?.accessToken || req.cookies?.token;
    const authHeader = req.headers?.authorization || '';

    if (!token && authHeader.startsWith('Bearer ')) {
        token = authHeader.slice(7).trim();
    } else if (!token && req.headers?.token) {
        token = req.headers.token;
    }

    if (!token) return null;

    try {
        let decoded = null;
        let isExpired = false;

        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (jwtErr) {
            if (jwtErr.name === 'TokenExpiredError') {
                isExpired = true;
                decoded = jwt.decode(token);
            } else {
                return null;
            }
        }

        if (!decoded || !decoded.sessionId) {
            return null;
        }

        const session = await findSessionById(decoded.sessionId);
        if (!session || !session.is_active) {
            return null;
        }

        // If session refresh window is expired, treat as inactive
        if (session.refresh_expires_at && new Date() > new Date(session.refresh_expires_at)) {
            await closeSession(session.id);
            return null;
        }

        return {
            session,
            decoded,
            token,
            isExpired,
            needsRefresh: isExpired
        };
    } catch (e) {
        return null;
    }
}

/**
 * Checks if the request is attempting to log in while an active session for another role/user exists.
 * Returns { hasConflict: boolean, message?: string, currentRole?: string, activeSession?: object }
 */
async function checkSessionConflict(req, targetRole, targetActorId = null, options = {}) {
    const active = await getActiveSessionFromRequest(req);
    if (!active || !active.session) {
        return { hasConflict: false };
    }

    // If caller specified forceLogout, terminate the existing conflicting session cleanly
    if (options.forceLogout) {
        await closeSession(active.session.id);
        return {
            hasConflict: false,
            wasTerminated: true,
            previousSession: active.session
        };
    }

    const existingRole = String(active.session.role || active.session.actor_type || '').toLowerCase();
    const reqTargetRole = String(targetRole || '').toLowerCase();

    const isExistingStudent = existingRole === 'student' || active.session.actor_type === 'STUDENT';
    const isTargetStudent = reqTargetRole === 'student';

    // Conflict Scenario 1: Cross-Role (Student active while attempting Authority login, or vice-versa)
    if (isExistingStudent !== isTargetStudent) {
        const currentRoleDisplay = active.session.role || (isExistingStudent ? 'student' : 'authority');
        return {
            hasConflict: true,
            activeSession: active.session,
            currentRole: currentRoleDisplay,
            currentActorId: active.session.actor_id,
            message: `An active session for '${currentRoleDisplay}' is already running in this browser. Please log out first before logging in as ${targetRole}.`
        };
    }

    // Conflict Scenario 2: Different user account within the same role category
    if (targetActorId && String(active.session.actor_id) !== String(targetActorId)) {
        return {
            hasConflict: true,
            activeSession: active.session,
            currentRole: active.session.role,
            currentActorId: active.session.actor_id,
            message: `Another ${isTargetStudent ? 'student' : 'authority'} account is already logged in on this browser. Please log out first.`
        };
    }

    return { hasConflict: false };
}

module.exports = {
    normalizeActorType,
    createSession,
    findSessionById,
    findActiveSession,
    closeSession,
    deactivateUserSessions,
    updateSessionRefresh,
    getActiveSessionFromRequest,
    checkSessionConflict,
};

