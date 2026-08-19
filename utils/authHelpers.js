const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    throw new Error('FATAL: JWT_SECRET environment variable is not defined.');
}

const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';

const DEFAULT_REFRESH_TOKEN_TTL_MS = Number(process.env.DEFAULT_REFRESH_TOKEN_TTL_MS) || (7 * 24 * 60 * 60 * 1000); // 7 days
const GUARD_REFRESH_TOKEN_TTL_MS = Number(process.env.GUARD_REFRESH_TOKEN_TTL_MS) || (30 * 24 * 60 * 60 * 1000); // 30 days

function getRefreshTokenExpiry(role) {
    const normalizedRole = String(role || '').trim().toLowerCase();
    if (normalizedRole === 'guard') {
        return GUARD_REFRESH_TOKEN_TTL_MS;
    }
    return DEFAULT_REFRESH_TOKEN_TTL_MS;
}

function getClientIp(req) {
    if (!req) return null;
    return req.ip || req.connection?.remoteAddress || null;
}

async function hashRefreshToken(token) {
    return bcrypt.hash(token, 10);
}

async function compareRefreshTokens(token, hash) {
    if (!token || !hash) return false;
    return bcrypt.compare(token, hash);
}

function generateRefreshToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateAccessToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
}

function getCookieOptions(req, maxAge = 30 * 24 * 60 * 60 * 1000) {
    const isProduction = process.env.NODE_ENV === "production" || Boolean(process.env.RENDER) || Boolean(process.env.RENDER_EXTERNAL_URL);
    return {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? "none" : "lax",
        path: "/",
        maxAge // default 30 days. Without maxAge, it becomes a "Session Cookie" and clears when tab/browser closes.
    };
}

module.exports = {
    JWT_SECRET,
    ACCESS_TOKEN_EXPIRY,
    getRefreshTokenExpiry,
    getClientIp,
    hashRefreshToken,
    compareRefreshTokens,
    generateRefreshToken,
    generateAccessToken,
    getCookieOptions,
};
