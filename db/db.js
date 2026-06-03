// db/db.js — PostgreSQL connection pool
// Used by every route that needs database access.
// Import with: const db = require('./db/db');

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // On Render, the connection string includes ?sslmode=require automatically.
  // Locally (Postgres.app) SSL is not needed.
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false,
});

// Expose a simple query helper so routes don't need to manage clients
module.exports = {
  query:   (text, params) => pool.query(text, params),
  pool,    // exposed for transactions if needed later
};
