const bcrypt = require('bcryptjs');

async function initDb(pool) {
    const conn = await pool.getConnection();
    try {
        // ── staff 테이블 생성 ──
        await conn.query(`
      CREATE TABLE IF NOT EXISTS staff (
        id                  INT AUTO_INCREMENT PRIMARY KEY,
        username            VARCHAR(50) UNIQUE NOT NULL,
        password            VARCHAR(255) NOT NULL,
        name                VARCHAR(100) NOT NULL,
        role                ENUM('admin','counselor') NOT NULL DEFAULT 'counselor',
        is_active           BOOLEAN DEFAULT TRUE,
        attendance_status   ENUM('offline','online') NOT NULL DEFAULT 'offline',
        checkin_at          TIMESTAMP NULL,
        last_login          TIMESTAMP NULL,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB COMMENT='관리자/상담원 계정'
    `);

        // ── attendance_status 컬럼 추가 (기존 테이블) ──
        const [attCols] = await conn.query(`
      SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'staff'
        AND COLUMN_NAME = 'attendance_status'
    `);
        if (attCols.length === 0) {
            await conn.query(`
        ALTER TABLE staff
        ADD COLUMN attendance_status ENUM('offline','online') NOT NULL DEFAULT 'offline',
        ADD COLUMN checkin_at TIMESTAMP NULL
      `);
            console.log('[DB] staff.attendance_status, checkin_at 컬럼 추가됨');
        }

        // ── call_session에 counselor_id 컬럼 추가 (없으면) ──
        const [cols] = await conn.query(`
      SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'call_session'
        AND COLUMN_NAME = 'counselor_id'
    `);
        if (cols.length === 0) {
            await conn.query(`
        ALTER TABLE call_session
        ADD COLUMN counselor_id INT NULL,
        ADD CONSTRAINT fk_counselor FOREIGN KEY (counselor_id) REFERENCES staff(id) ON DELETE SET NULL
      `);
            console.log('[DB] call_session.counselor_id 컬럼 추가됨');
        }

        // ── 기본 admin 계정 생성 (없으면) ──
        const [admins] = await conn.query(`SELECT id FROM staff WHERE username = 'admin'`);
        if (admins.length === 0) {
            const hash = await bcrypt.hash('admin1234', 10);
            await conn.query(
                `INSERT INTO staff (username, password, name, role) VALUES ('admin', ?, '관리자', 'admin')`,
                [hash]
            );
            console.log('[DB] 기본 admin 계정 생성됨 (admin / admin1234)');
        }

        console.log('[DB] 초기화 완료');
    } finally {
        conn.release();
    }
}

module.exports = { initDb };
