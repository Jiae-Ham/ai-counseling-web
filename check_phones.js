const mysql = require('mysql2/promise');
(async () => {
    const db = await mysql.createConnection({
        host: 'localhost', port: 13306,
        user: 'counseling_user', password: 'counseling_pass',
        database: 'ai_counseling'
    });

    console.log('\n=== 대화 있는 세션 + 유저 전화번호 ===');
    const [rows] = await db.query(`
    SELECT cs.id as session_id, u.id as user_id, u.name, u.phone, u.address,
           (SELECT COUNT(*) FROM conversation_message cm WHERE cm.session_id = cs.id) as msg_count
    FROM call_session cs
    JOIN users u ON cs.user_id = u.id
    WHERE (SELECT COUNT(*) FROM conversation_message cm WHERE cm.session_id = cs.id) > 0
    ORDER BY cs.id
    LIMIT 25
  `);
    console.table(rows);

    console.log('\n=== users 테이블 phone 필드 통계 ===');
    const [stats] = await db.query(`
    SELECT
      COUNT(*) as total_users,
      SUM(phone IS NOT NULL) as has_phone,
      SUM(phone IS NULL) as no_phone
    FROM users
  `);
    console.table(stats);

    await db.end();
})();
