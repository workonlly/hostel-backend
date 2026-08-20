const fs = require("fs");
const path = require("path");

const LOGS_DIR = path.join(__dirname, "..", "logs");

// Ensure logs directory exists
if (!fs.existsSync(LOGS_DIR)) {
    try {
        fs.mkdirSync(LOGS_DIR, { recursive: true });
    } catch (err) {
        console.error("Failed to create logs directory:", err.message);
    }
}

const APP_LOG_PATH = path.join(LOGS_DIR, "app.log");
const ERROR_LOG_PATH = path.join(LOGS_DIR, "error.log");
const DB_LOG_PATH = path.join(LOGS_DIR, "db.log");

// Maximum log file size: 10 MB before rolling
const MAX_LOG_SIZE_BYTES = 10 * 1024 * 1024;

/**
 * Check file size and rotate if necessary (app.log -> app.log.1)
 */
function checkAndRotate(filePath) {
    try {
        if (fs.existsSync(filePath)) {
            const stats = fs.statSync(filePath);
            if (stats.size >= MAX_LOG_SIZE_BYTES) {
                const rotatedPath = `${filePath}.${Date.now()}.bak`;
                fs.renameSync(filePath, rotatedPath);
            }
        }
    } catch (e) {
        // Ignore rotation errors to prevent app crashes
    }
}

/**
 * Append formatted log entry to file
 */
function appendToFile(filePath, content) {
    try {
        checkAndRotate(filePath);
        fs.appendFileSync(filePath, content + "\n", "utf8");
    } catch (err) {
        // Fallback to console if file system write fails
        console.error(`[LOGGER FILE WRITE ERROR]: ${err.message}`);
    }
}

/**
 * Format log message with ISO timestamp and metadata
 */
function formatMessage(level, tag, message, context = null) {
    const timestamp = new Date().toISOString();
    let entry = `[${timestamp}] [${level}] [${tag || "SYSTEM"}] ${message}`;

    if (context) {
        if (context instanceof Error) {
            entry += `\n  Error: ${context.message}\n  Stack: ${context.stack}`;
        } else if (typeof context === "object") {
            try {
                entry += `\n  Context: ${JSON.stringify(context)}`;
            } catch (_) {
                entry += `\n  Context: [Unserializable Object]`;
            }
        } else {
            entry += ` | Context: ${context}`;
        }
    }
    return entry;
}

const logger = {
    /**
     * Standard Informational Log
     */
    info: (message, context = null, tag = "INFO") => {
        const formatted = formatMessage("INFO", tag, message, context);
        console.log(`\x1b[32m${formatted}\x1b[0m`);
        appendToFile(APP_LOG_PATH, formatted);
    },

    /**
     * Warning Log
     */
    warn: (message, context = null, tag = "WARN") => {
        const formatted = formatMessage("WARN", tag, message, context);
        console.warn(`\x1b[33m${formatted}\x1b[0m`);
        appendToFile(APP_LOG_PATH, formatted);
    },

    /**
     * General Application Error Log
     */
    error: (message, error = null, context = null, tag = "ERROR") => {
        const combinedContext = error ? { error: error.message || error, stack: error.stack, ...(context || {}) } : context;
        const formatted = formatMessage("ERROR", tag, message, combinedContext);
        console.error(`\x1b[31m${formatted}\x1b[0m`);
        appendToFile(APP_LOG_PATH, formatted);
        appendToFile(ERROR_LOG_PATH, formatted);
    },

    /**
     * Database Operations & Query Log
     */
    db: (message, context = null) => {
        const formatted = formatMessage("DB_INFO", "DATABASE", message, context);
        console.log(`\x1b[36m${formatted}\x1b[0m`);
        appendToFile(APP_LOG_PATH, formatted);
        appendToFile(DB_LOG_PATH, formatted);
    },

    /**
     * Database Failures, Connection Drops & Query Errors
     */
    dbError: (error, queryInfo = null, context = null) => {
        const payload = {
            errorMessage: error?.message || error,
            errorCode: error?.code,
            query: queryInfo?.text || queryInfo,
            params: queryInfo?.values,
            stack: error?.stack,
            ...(context || {})
        };
        const formatted = formatMessage("DB_ERROR", "DATABASE_FAIL", `Database Error: ${error?.message || "Unknown DB error"}`, payload);
        console.error(`\x1b[41m\x1b[37m${formatted}\x1b[0m`);
        appendToFile(APP_LOG_PATH, formatted);
        appendToFile(ERROR_LOG_PATH, formatted);
        appendToFile(DB_LOG_PATH, formatted);
    },

    /**
     * Security & Intrusion Alerts (Rate limit, CSRF, Invalid Auth)
     */
    security: (message, context = null) => {
        const formatted = formatMessage("SECURITY", "AUTH_GUARD", message, context);
        console.warn(`\x1b[35m${formatted}\x1b[0m`);
        appendToFile(APP_LOG_PATH, formatted);
        appendToFile(ERROR_LOG_PATH, formatted);
    },

    /**
     * Fatal Uncaught Crashes
     */
    fatal: (message, error = null, context = null) => {
        const combinedContext = error ? { error: error.message || error, stack: error.stack, ...(context || {}) } : context;
        const formatted = formatMessage("FATAL", "CRITICAL_CRASH", message, combinedContext);
        console.error(`\x1b[41m\x1b[37m${formatted}\x1b[0m`);
        appendToFile(APP_LOG_PATH, formatted);
        appendToFile(ERROR_LOG_PATH, formatted);
        appendToFile(DB_LOG_PATH, formatted);
    },

    /**
     * Express HTTP Request & Response Monitoring Middleware
     */
    requestMiddleware: () => {
        return (req, res, next) => {
            const start = performance.now();
            const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || req.ip || "unknown";

            res.on("finish", () => {
                const durationMs = (performance.now() - start).toFixed(2);
                const statusCode = res.statusCode;
                const logMessage = `${req.method} ${req.originalUrl || req.url} -> ${statusCode} (${durationMs}ms) [IP: ${ip}]`;

                const reqContext = {
                    method: req.method,
                    url: req.originalUrl || req.url,
                    status: statusCode,
                    durationMs: parseFloat(durationMs),
                    ip,
                    userAgent: req.headers["user-agent"]
                };

                if (statusCode >= 500) {
                    logger.error(`HTTP Server Error: ${logMessage}`, null, reqContext, "HTTP_5XX");
                } else if (statusCode >= 400) {
                    logger.warn(`HTTP Client Warning: ${logMessage}`, reqContext, "HTTP_4XX");
                } else {
                    const formatted = formatMessage("HTTP", "ACCESS", logMessage);
                    appendToFile(APP_LOG_PATH, formatted);
                }
            });

            next();
        };
    }
};

// Global Crash Handlers for unhandled exceptions & promise rejections
process.on("uncaughtException", (err) => {
    logger.fatal("Uncaught Exception detected in Node.js process", err);
});

process.on("unhandledRejection", (reason, promise) => {
    logger.fatal("Unhandled Promise Rejection detected", reason instanceof Error ? reason : new Error(String(reason)));
});

module.exports = logger;
