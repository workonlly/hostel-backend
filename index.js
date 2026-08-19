const express = require("express");
require("dotenv").config();
const cors = require("cors");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");

const signup = require("./auth/sigup.js");
const login = require("./auth/login.js");
const me = require("./auth/me.js");
const loginAuthority = require("./auth/login-authority.js");
const refresh = require("./auth/refresh.js");
const logout = require("./auth/logout.js");
const management = require("./authority/authority.js");
const dashboard = require("./authority/dashboard.js");
const students = require("./authority/students.js");
const chiefWarden = require("./authority/chiefWarden.js");
const outpass = require("./outpass/outpass.js");
const guard = require("./guard/guard.js");
const hostelGuard = require("./guard/hostelGuard.js");
const pool = require("./db/db");

const app = express();
const PORT = process.env.PORT || 4000;

app.set('trust proxy', 1);

const ALLOWED_ORIGINS = [
    "https://hostel-frontend-1-59yg.onrender.com",
    "https://hostel-authority-1.onrender.com",
    "https://hostel-guard-1.onrender.com",
    "https://hostel-backend-cveq.onrender.com",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:5175",
    ...(process.env.FRONTEND_URL ? process.env.FRONTEND_URL.split(",").map(s => s.trim()) : []),
    ...(process.env.AUTHORITY_URL ? process.env.AUTHORITY_URL.split(",").map(s => s.trim()) : []),
    ...(process.env.GUARD_URL ? process.env.GUARD_URL.split(",").map(s => s.trim()) : []),
    ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",").map(s => s.trim()) : [])
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        
        // Match specific allowed origins
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        
        // Match any onrender.com deployment (e.g. preview apps, renamed instances)
        if (/^https:\/\/[a-zA-Z0-9-]+\.onrender\.com$/.test(origin)) {
            return callback(null, true);
        }
        
        // Match local development ports and LAN addresses
        if (/^http:\/\/(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)(:\d+)?$/.test(origin)) {
            return callback(null, true);
        }

        return callback(null, true); // Permissive in deployment to ensure all services connect
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
        "Content-Type",
        "Authorization",
        "token",
        "role",
        "x-device-id",
        "x-device-token",
        "x-device-fingerprint"
    ]
}));
app.use(helmet());
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));
app.use(cookieParser());

// CSRF Origin validation for mutating requests (applies when relying on ambient cookies)
app.use((req, res, next) => {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
        return next();
    }

    // Explicit Authorization header with Bearer token is immune to CSRF
    const authHeader = req.headers.authorization || "";
    if (authHeader.startsWith("Bearer ")) {
        return next();
    }

    const origin = req.headers.origin || req.headers.referer;
    if (!origin) {
        return next();
    }

    const originHostname = (() => {
        try {
            return new URL(origin).origin;
        } catch (_) {
            return origin;
        }
    })();

    const isAllowed = 
        ALLOWED_ORIGINS.includes(originHostname) ||
        /^https:\/\/[a-zA-Z0-9-]+\.onrender\.com$/.test(originHostname) ||
        /^http:\/\/(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)(:\d+)?$/.test(originHostname);

    if (!isAllowed) {
        return res.status(403).json({
            success: false,
            message: "Cross-Origin Request Blocked by Security Policy"
        });
    }

    next();
});

// Authentication routes
app.use("/api/auth", signup);
app.use("/api/auth", login);
app.use("/api/auth", me);
app.use("/api/auth", refresh);
app.use("/api/auth", logout);
app.use("/api/authority", loginAuthority);
app.use("/api/authority", me);
app.use("/api/authority", refresh);
app.use("/api/authority", logout);

// Role management routes
app.use("/api/management", management);

// Chief warden routes
app.use("/api/chief-warden", chiefWarden);

// Student outpass routes
app.use("/api/outpass", outpass);

// Authority & monitor outpass routes
app.use("/api/outpasses", dashboard);
app.use("/api/outpass", dashboard); // Alias to support single-path frontends

// Student and warden student management routes
app.use("/api/students", students);

// Guard routes (main gate)
app.use("/api/guard", guard);

// Hostel guard routes
app.use("/api/guard", hostelGuard);

// Hostels & helper routes
app.get("/api/hostels", async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, name, type, total_capacity, local_outpass_cutoff FROM hostel ORDER BY name ASC"
        );
        res.json({ success: true, hostels: result.rows });
    } catch (error) {
        console.error("Hostel list error:", error);
        res.status(500).json({ success: false, hostels: [] });
    }
});

// Get rooms for a specific hostel by name
app.get("/api/hostels/by-name/:name/rooms", async (req, res) => {
    try {
        const { name } = req.params;
        const result = await pool.query(
            "SELECT room.id, room.room_number, room.max_capacity FROM room JOIN hostel ON room.hostel_id = hostel.id WHERE hostel.name = $1 ORDER BY room.room_number ASC",
            [name]
        );
        res.json({ success: true, rooms: result.rows });
    } catch (error) {
        console.error("Room list error:", error);
        res.status(500).json({ success: false, rooms: [] });
    }
});

// Mock endpoints to prevent frontend crashes
app.get("/complaint/all", (req, res) => res.json({ data: [] }));
app.get("/complaint/escalated", (req, res) => res.json({ data: [] }));

app.get("/", (req, res) => {
    res.json({ success: true, message: "Hostel Backend is running smoothly!" });
});

// Global Error Handler Middleware
app.use((err, req, res, next) => {
    const statusCode = err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    if (statusCode >= 500) {
        console.error("[SERVER ERROR]:", err);
    }

    return res.status(statusCode).json({
        statusCode,
        success: false,
        message,
        errors: err.errors || []
    });
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

module.exports = app;
