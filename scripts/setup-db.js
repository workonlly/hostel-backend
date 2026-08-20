require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const pool = require('../db/db');
const fs = require('fs');
const path = require('path');

async function runMigration() {
    try {
        console.log('Reading db.sql file...');
        const sqlFilePath = path.resolve(__dirname, '../db/db.sql');
        const sqlQuery = fs.readFileSync(sqlFilePath, 'utf8');

        console.log('Executing SQL script to create tables...');
        await pool.query(sqlQuery);
        
        console.log('✅ Database tables created successfully!');
        process.exit(0); // Exit successfully
    } catch (error) {
        console.error('❌ Error executing SQL:', error.message);
        process.exit(1); // Exit with failure
    }
}

runMigration();