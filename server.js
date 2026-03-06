require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const path = require('path');
const { initDb } = require('./db-init');

const app = express();
const PORT = process.env.PORT || 3001;

// ── DB Pool ──
const poolOpts = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT) || 13306,
  database: process.env.DB_NAME || 'ai_counseling',
  user: process.env.DB_USER || 'counseling_user',
  password: process.env.DB_PASSWORD || 'counseling_pass',
  waitForConnections: true,
  connectionLimit: 10,
};
const pool = mysql.createPool(poolOpts);


// ── Session Store (MySQL) ──
const sessionStore = new MySQLStore({
  host: poolOpts.host,
  port: poolOpts.port,
  database: poolOpts.database,
  user: poolOpts.user,
  password: poolOpts.password,
  clearExpired: true,
  checkExpirationInterval: 900000,
  expiration: 86400000,
});

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'ai-counseling-secret-2024',
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {}, // 브라우저 닫으면 세션 쿠키 삭제 (로그아웃)
}));

// ── 정적 파일 ──
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth 미들웨어 ──
function requireAuth(req, res, next) {
  if (!req.session.staff) return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.staff) return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
  if (req.session.staff.role !== 'admin') return res.status(403).json({ success: false, message: '관리자 권한이 필요합니다.' });
  next();
}

// ═══════════════════════════════════════════
// AUTH APIs
// ═══════════════════════════════════════════

// 로그인
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: '아이디와 비밀번호를 입력하세요.' });
  try {
    const [rows] = await pool.query('SELECT * FROM staff WHERE username = ? AND is_active = TRUE', [username]);
    if (rows.length === 0) return res.status(401).json({ success: false, message: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    const staff = rows[0];
    const ok = await bcrypt.compare(password, staff.password);
    if (!ok) return res.status(401).json({ success: false, message: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    // last_login 갱신
    await pool.query('UPDATE staff SET last_login = NOW() WHERE id = ?', [staff.id]);
    req.session.staff = { id: staff.id, username: staff.username, name: staff.name, role: staff.role };
    res.json({ success: true, data: req.session.staff });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// 로그아웃
app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// 익스포트: 현재 세션 정보
app.get('/api/auth/me', (req, res) => {
  if (!req.session.staff) return res.json({ success: false });
  res.json({ success: true, data: req.session.staff });
});

// ═══════════════════════════════════════════
// 상담원 출근/퇴근 APIs
// ═══════════════════════════════════════════

// 출근
app.post('/api/counselor/checkin', requireAuth, async (req, res) => {
  const { id } = req.session.staff;
  try {
    const now = new Date();
    await pool.query(
      `UPDATE staff SET attendance_status = 'online', checkin_at = ? WHERE id = ?`, [now, id]
    );
    res.json({ success: true, status: 'online', checkin_at: now });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 퇴근
app.post('/api/counselor/checkout', requireAuth, async (req, res) => {
  const { id } = req.session.staff;
  try {
    await pool.query(
      `UPDATE staff SET attendance_status = 'offline', checkin_at = NULL WHERE id = ?`, [id]
    );
    res.json({ success: true, status: 'offline' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 상담원: 자신의 출근 상태 조회
app.get('/api/counselor/attendance-status', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT attendance_status, checkin_at FROM staff WHERE id = ?', [req.session.staff.id]
    );
    if (!rows.length) return res.status(404).json({ success: false });
    res.json({ success: true, data: rows[0] });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ═══════════════════════════════════════════
// ADMIN APIs
// ═══════════════════════════════════════════

// 상담원 목록
app.get('/api/admin/staff', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, username, name, role, is_active, attendance_status, checkin_at, last_login, created_at,
              (SELECT COUNT(*) FROM call_session WHERE counselor_id = staff.id) as assigned_count
       FROM staff ORDER BY role, created_at`
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 상담원 계정 생성
app.post('/api/admin/staff', requireAdmin, async (req, res) => {
  const { username, password, name, role = 'counselor' } = req.body;
  if (!username || !password || !name) return res.status(400).json({ success: false, message: '필수 항목을 입력하세요.' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO staff (username, password, name, role) VALUES (?, ?, ?, ?)',
      [username, hash, name, role]
    );
    res.json({ success: true, data: { id: result.insertId, username, name, role } });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: '이미 사용 중인 아이디입니다.' });
    res.status(500).json({ success: false, message: e.message });
  }
});

// 상담원 활성/비활성 토글
app.patch('/api/admin/staff/:id/toggle', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE staff SET is_active = NOT is_active WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 상담원 비밀번호 강제 변경 (관리자 전용)
app.patch('/api/admin/staff/:id/password', requireAdmin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ success: false, message: '새 비밀번호를 4자 이상 입력하세요.' });
  try {
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE staff SET password = ? WHERE id = ?', [hash, req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 상담원 삭제
app.delete('/api/admin/staff/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE call_session SET counselor_id = NULL WHERE counselor_id = ?', [req.params.id]);
    await pool.query('DELETE FROM staff WHERE id = ? AND role != "admin"', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── 공통 필터 조건 설명 ──
// 조건1: 첫 번째 user 메시지에 '감사합니다' / '감자합니다' / '감자입니다' 포함 시 제외
// 조건2: 세션 전체 user 메시지가 모두 '어+' 형태만인 경우 제외

// 미배분 세션 목록 (관리자용) — 대화 있는 세션만
app.get('/api/admin/sessions/unassigned', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT cs.id, cs.session_id, cs.status, cs.start_at, cs.end_at,
              u.name, u.phone,
              (SELECT COUNT(*) FROM conversation_message WHERE session_id = cs.id) as msg_count
       FROM call_session cs
       JOIN users u ON cs.user_id = u.id
       WHERE cs.counselor_id IS NULL
         AND (SELECT COUNT(*) FROM conversation_message WHERE session_id = cs.id) > 0
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감사합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자입니다%'
         AND NOT (
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user') > 0
           AND
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user'
              AND TRIM(cm.content) NOT REGEXP '^어+$') = 0
         )
       ORDER BY cs.start_at DESC`
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 특정 상담원의 배분 세션 목록 (관리자용) — 대화 있는 세션만
app.get('/api/admin/staff/:id/sessions', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT cs.id, cs.session_id, cs.status, cs.start_at, cs.end_at,
              u.name, u.phone,
              (SELECT COUNT(*) FROM conversation_message WHERE session_id = cs.id) as msg_count
       FROM call_session cs
       JOIN users u ON cs.user_id = u.id
       WHERE cs.counselor_id = ?
         AND (SELECT COUNT(*) FROM conversation_message WHERE session_id = cs.id) > 0
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감사합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자입니다%'
         AND NOT (
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user') > 0
           AND
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user'
              AND TRIM(cm.content) NOT REGEXP '^어+$') = 0
         )
       ORDER BY cs.start_at DESC`,
      [req.params.id]
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 수동 배분: 특정 세션을 특정 상담원에게 할당
app.post('/api/admin/assign', requireAdmin, async (req, res) => {
  const { sessionIds, counselorId } = req.body;
  if (!sessionIds?.length || !counselorId) return res.status(400).json({ success: false, message: '세션 ID와 상담원을 선택하세요.' });
  try {
    const placeholders = sessionIds.map(() => '?').join(',');
    await pool.query(
      `UPDATE call_session SET counselor_id = ? WHERE id IN (${placeholders})`,
      [counselorId, ...sessionIds]
    );
    res.json({ success: true, assigned: sessionIds.length });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 배분 취소 (상담원에서 제거)
app.post('/api/admin/unassign', requireAdmin, async (req, res) => {
  const { sessionIds } = req.body;
  if (!sessionIds?.length) return res.status(400).json({ success: false, message: '세션 ID를 선택하세요.' });
  try {
    const placeholders = sessionIds.map(() => '?').join(',');
    await pool.query(`UPDATE call_session SET counselor_id = NULL WHERE id IN (${placeholders})`, sessionIds);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 자동 배분: 출근 중인 상담원에게 미배분 세션 라운드로빈
app.post('/api/admin/auto-assign', requireAdmin, async (req, res) => {
  const { perCounselor = 5 } = req.body;
  try {
    // 1. 출근 중인 상담원 목록
    const [counselors] = await pool.query(
      `SELECT id, name FROM staff WHERE role = 'counselor' AND is_active = TRUE AND attendance_status = 'online' ORDER BY id`
    );
    if (!counselors.length) return res.status(400).json({ success: false, message: '출근 중인 상담원이 없습니다.' });

    // 2. 미배분 세션 목록 (오래된 순, 출근 인원 * perCounselor 만큼)
    const limit = counselors.length * parseInt(perCounselor);
    const [sessions] = await pool.query(
      `SELECT cs.id FROM call_session cs
       WHERE cs.counselor_id IS NULL
         AND (SELECT COUNT(*) FROM conversation_message WHERE session_id = cs.id) > 0
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감사합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자입니다%'
         AND NOT (
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user') > 0
           AND
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user'
              AND TRIM(cm.content) NOT REGEXP '^어+$') = 0
         )
       ORDER BY cs.start_at ASC LIMIT ?`,
      [limit]
    );
    if (!sessions.length) return res.status(400).json({ success: false, message: '미배분 상담이 없습니다.' });

    // 3. 라운드로빈 배분
    const results = {};
    counselors.forEach(c => { results[c.id] = { name: c.name, count: 0 }; });
    for (let i = 0; i < sessions.length; i++) {
      const c = counselors[i % counselors.length];
      await pool.query('UPDATE call_session SET counselor_id = ? WHERE id = ?', [c.id, sessions[i].id]);
      results[c.id].count++;
    }

    const summary = Object.values(results).filter(r => r.count > 0);
    res.json({
      success: true,
      total: sessions.length,
      counselorCount: summary.length,
      details: summary,
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 출근 상담원 목록 (관리자용)
app.get('/api/admin/attendance', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, name, attendance_status, checkin_at,
              (SELECT COUNT(*) FROM call_session WHERE counselor_id = staff.id) as assigned_count
       FROM staff WHERE role = 'counselor' AND is_active = TRUE ORDER BY attendance_status DESC, checkin_at ASC`
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ═══════════════════════════════════════════
// 전체 상담 조회 (관리자 전용) — 전화번호 기반
// ═══════════════════════════════════════════

// 전화번호별 그룹 목록 (대화 있는 세션만)
app.get('/api/admin/phones', requireAdmin, async (req, res) => {
  try {
    const { dateFrom, dateTo } = req.query;
    let dateWhere = '';
    const params = [];
    if (dateFrom) { dateWhere += ' AND cs.start_at >= ?'; params.push(dateFrom + ' 00:00:00'); }
    if (dateTo) { dateWhere += ' AND cs.start_at <= ?'; params.push(dateTo + ' 23:59:59'); }
    const [rows] = await pool.query(
      `SELECT
         COALESCE(u.phone, CONCAT('uid-', CAST(u.id AS CHAR))) AS phone_key,
         u.phone,
         COUNT(DISTINCT cs.id) AS session_count,
         MAX(cs.start_at) AS latest_at
       FROM users u
       JOIN call_session cs ON cs.user_id = u.id
       WHERE (SELECT COUNT(*) FROM conversation_message cm WHERE cm.session_id = cs.id) > 0
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감사합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자입니다%'
         AND NOT (
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user') > 0
           AND
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user'
              AND TRIM(cm.content) NOT REGEXP '^어+$') = 0
         )
         ${dateWhere}
       GROUP BY COALESCE(u.phone, CONCAT('uid-', CAST(u.id AS CHAR))), u.phone
       ORDER BY MAX(cs.start_at) DESC`,
      params
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 특정 전화번호의 세션 목록 (대화 있는 것만)
app.get('/api/admin/phones/:phoneKey/sessions', requireAdmin, async (req, res) => {
  try {
    const key = decodeURIComponent(req.params.phoneKey);
    const { dateFrom, dateTo } = req.query;
    let whereClause, params;
    if (key.startsWith('uid-')) {
      whereClause = 'cs.user_id = ?';
      params = [parseInt(key.replace('uid-', ''))];
    } else {
      whereClause = 'u.phone = ?';
      params = [key];
    }
    if (dateFrom) { whereClause += ' AND cs.start_at >= ?'; params.push(dateFrom + ' 00:00:00'); }
    if (dateTo) { whereClause += ' AND cs.start_at <= ?'; params.push(dateTo + ' 23:59:59'); }
    const [rows] = await pool.query(
      `SELECT cs.id, cs.session_id, cs.status, cs.review_status, cs.start_at, cs.end_at,
              u.name, u.phone,
              s.name AS counselor_name,
              (SELECT COUNT(*) FROM conversation_message cm WHERE cm.session_id = cs.id) AS msg_count
       FROM call_session cs
       JOIN users u ON cs.user_id = u.id
       LEFT JOIN staff s ON cs.counselor_id = s.id
       WHERE ${whereClause}
         AND (SELECT COUNT(*) FROM conversation_message cm WHERE cm.session_id = cs.id) > 0
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감사합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자입니다%'
         AND NOT (
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user') > 0
           AND
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user'
              AND TRIM(cm.content) NOT REGEXP '^어+$') = 0
         )
       ORDER BY cs.start_at DESC`,
      params
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ═══════════════════════════════════════════
// 상담원 전용 APIs — 전화번호 기반
// ═══════════════════════════════════════════

// 상담원: 자신의 배분된 전화번호 그룹
app.get('/api/counselor/phones', requireAuth, async (req, res) => {
  if (req.session.staff.role !== 'counselor') return res.status(403).json({ success: false, message: '권한 없음' });
  try {
    const [rows] = await pool.query(
      `SELECT
         COALESCE(u.phone, CONCAT('uid-', CAST(u.id AS CHAR))) AS phone_key,
         u.phone,
         COUNT(DISTINCT cs.id) AS session_count,
         MAX(cs.start_at) AS latest_at
       FROM users u
       JOIN call_session cs ON cs.user_id = u.id
       WHERE cs.counselor_id = ?
         AND (SELECT COUNT(*) FROM conversation_message cm WHERE cm.session_id = cs.id) > 0
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감사합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자입니다%'
         AND NOT (
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user') > 0
           AND
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user'
              AND TRIM(cm.content) NOT REGEXP '^어+$') = 0
         )
       GROUP BY COALESCE(u.phone, CONCAT('uid-', CAST(u.id AS CHAR))), u.phone
       ORDER BY MAX(cs.start_at) DESC`,
      [req.session.staff.id]
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 상담원: 특정 전화번호의 세션 목록
app.get('/api/counselor/phones/:phoneKey/sessions', requireAuth, async (req, res) => {
  if (req.session.staff.role !== 'counselor') return res.status(403).json({ success: false, message: '권한 없음' });
  try {
    const key = decodeURIComponent(req.params.phoneKey);
    let whereClause, params;
    if (key.startsWith('uid-')) {
      whereClause = 'cs.user_id = ? AND cs.counselor_id = ?';
      params = [parseInt(key.replace('uid-', '')), req.session.staff.id];
    } else {
      whereClause = 'u.phone = ? AND cs.counselor_id = ?';
      params = [key, req.session.staff.id];
    }
    const [rows] = await pool.query(
      `SELECT cs.id, cs.session_id, cs.status, cs.review_status, cs.start_at, cs.end_at,
              u.name, u.phone,
              (SELECT COUNT(*) FROM conversation_message cm WHERE cm.session_id = cs.id) AS msg_count
       FROM call_session cs
       JOIN users u ON cs.user_id = u.id
       WHERE ${whereClause}
         AND (SELECT COUNT(*) FROM conversation_message cm WHERE cm.session_id = cs.id) > 0
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감사합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자합니다%'
         AND (SELECT TRIM(cm_f.content) FROM conversation_message cm_f
              WHERE cm_f.session_id = cs.id AND cm_f.role = 'user'
              ORDER BY cm_f.created_at ASC LIMIT 1) NOT LIKE '%감자입니다%'
         AND NOT (
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user') > 0
           AND
           (SELECT COUNT(*) FROM conversation_message cm
            WHERE cm.session_id = cs.id AND cm.role = 'user'
              AND TRIM(cm.content) NOT REGEXP '^어+$') = 0
         )
       ORDER BY cs.start_at DESC`,
      params
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});


// ═══════════════════════════════════════════
// 공용: 세션의 대화 내역 (권한 체크 포함)

// ═══════════════════════════════════════════
app.get('/api/sessions/:sessionId/messages', requireAuth, async (req, res) => {
  const { sessionId } = req.params;
  try {
    // 상담원이면 자신의 배분인지 확인
    if (req.session.staff.role === 'counselor') {
      const [check] = await pool.query(
        'SELECT id FROM call_session WHERE id = ? AND counselor_id = ?',
        [sessionId, req.session.staff.id]
      );
      if (check.length === 0) return res.status(403).json({ success: false, message: '접근 권한이 없습니다.' });
    }
    const [rows] = await pool.query(
      'SELECT id, role, content, created_at FROM conversation_message WHERE session_id = ? ORDER BY created_at ASC',
      [sessionId]
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ═══════════════════════════════════════════
// 세션 메모 (상담원 전용)
// ═══════════════════════════════════════════

// 메모 조회
app.get('/api/sessions/:sessionId/memo', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT memo FROM session_memo WHERE session_id = ? AND staff_id = ?',
      [req.params.sessionId, req.session.staff.id]
    );
    res.json({ success: true, memo: rows.length ? rows[0].memo : '' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 메모 저장
app.put('/api/sessions/:sessionId/memo', requireAuth, async (req, res) => {
  const { memo } = req.body;
  try {
    await pool.query(
      `INSERT INTO session_memo (session_id, staff_id, memo) VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE memo = ?, updated_at = NOW()`,
      [req.params.sessionId, req.session.staff.id, memo, memo]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 검토 상태 변경
app.patch('/api/sessions/:sessionId/review-status', requireAuth, async (req, res) => {
  const { status } = req.body;
  const allowed = ['미확인', '가망', '비가망'];
  if (!allowed.includes(status)) return res.status(400).json({ success: false, message: '유효하지 않은 상태' });
  try {
    await pool.query(
      'UPDATE call_session SET review_status = ? WHERE id = ?',
      [status, req.params.sessionId]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 세션 삭제 (관리자 전용)
app.delete('/api/admin/sessions/:sessionId', requireAdmin, async (req, res) => {
  try {
    const id = req.params.sessionId;
    await pool.query('DELETE FROM session_memo WHERE session_id = ?', [id]);
    await pool.query('DELETE FROM conversation_message WHERE session_id = ?', [id]);
    await pool.query('DELETE FROM call_session WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ═══════════════════════════════════════════
// Health
// ═══════════════════════════════════════════
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ success: true, message: 'DB 연결 정상' });
  } catch (e) { res.status(500).json({ success: false, message: 'DB 연결 실패: ' + e.message }); }
});

// ── 서버 시작 ──
(async () => {
  await initDb(pool);
  app.listen(PORT, () => {
    console.log(`🚀 AI Counseling Admin: http://localhost:${PORT}`);
    console.log(`📦 DB: ${poolOpts.host}:${poolOpts.port}/${poolOpts.database}`);
  });
})();
