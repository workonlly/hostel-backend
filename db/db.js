const { Pool } = require("pg");
require("dotenv").config();
const logger = require("../utils/logger");

const connectionString = process.env.DATABASE_URL || "";

// Detect if cloud database requiring SSL
const isCloudDb = connectionString.includes("neon.tech") || 
                  connectionString.includes("render.com") || 
                  process.env.NODE_ENV === "production" || 
                  process.env.DB_SSL === "true";

const pool = new Pool({
  connectionString,
  ssl: isCloudDb ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on("connect", () => {
  logger.db("Successfully established connection to PostgreSQL database");
});

pool.on("error", (err) => {
  logger.dbError(err, null, { context: "Unexpected error on idle PostgreSQL pool client" });
  // Do not kill process on idle client drop from Neon serverless
});

// Intercept and wrap pool.query to automatically log any query failures
const originalQuery = pool.query.bind(pool);
pool.query = async function (text, params, callback) {
  try {
    return await originalQuery(text, params, callback);
  } catch (err) {
    logger.dbError(err, { text, values: params }, { context: "Database query execution failure" });
    throw err;
  }
};

module.exports = pool;
