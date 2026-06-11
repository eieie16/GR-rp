const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'grimward_secret_key_2025';

function json(res, data, status = 200) {
  res.status(status).json(data);
}

function verifyToken(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  try {
    return jwt.verify(auth.split(' ')[1], JWT_SECRET);
  } catch {
    return null;
  }
}

module.exports = async (req, res) => {
  // 设置 CORS 头
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const url = req.url;
  const method = req.method;

  try {
    // 注册
    if (url === '/api/auth/register' && method === 'POST') {
      const { username, password, inviteCode } = req.body;
      if (!username || !password || !inviteCode) return json(res, { error: '请填写完整' }, 400);
      const inviteRes = await pool.query('SELECT * FROM invites WHERE code = $1 AND used_by IS NULL', [inviteCode]);
      if (inviteRes.rows.length === 0) return json(res, { error: '无效邀请码' }, 400);
      const userExists = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      if (userExists.rows.length > 0) return json(res, { error: '用户名已存在' }, 400);
      const hashed = bcrypt.hashSync(password, 10);
      await pool.query('INSERT INTO users (username, password, reg_date, points) VALUES ($1, $2, NOW(), 100)', [username, hashed]);
      await pool.query('UPDATE invites SET used_by = $1 WHERE code = $2', [username, inviteCode]);
      return json(res, { success: true }, 201);
    }

    // 登录
    if (url === '/api/auth/login' && method === 'POST') {
      const { username, password } = req.body;
      const userRes = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      if (userRes.rows.length === 0) return json(res, { error: '用户名或密码错误' }, 401);
      const user = userRes.rows[0];
      if (!bcrypt.compareSync(password, user.password)) return json(res, { error: '用户名或密码错误' }, 401);
      const token = jwt.sign({ id: user.id, username: user.username, isAdmin: user.is_admin === 1 }, JWT_SECRET, { expiresIn: '7d' });
      return json(res, { token, username: user.username, isAdmin: user.is_admin === 1 });
    }

    // 获取用户信息
    if (url === '/api/user/profile' && method === 'GET') {
      const user = verifyToken(req);
      if (!user) return json(res, { error: '未登录' }, 401);
      const dbUser = await pool.query('SELECT username, points, is_vip, is_admin, avatar, reg_date, title FROM users WHERE id = $1', [user.id]);
      if (dbUser.rows.length === 0) return json(res, { error: '用户不存在' }, 404);
      return json(res, dbUser.rows[0]);
    }

    // 兑换码
    if (url === '/api/user/redeem' && method === 'POST') {
      const user = verifyToken(req);
      if (!user) return json(res, { error: '未登录' }, 401);
      const { code } = req.body;
      const redeemRes = await pool.query('SELECT * FROM redeem_codes WHERE code = $1', [code]);
      if (redeemRes.rows.length === 0) return json(res, { error: '无效兑换码' }, 400);
      const redeem = redeemRes.rows[0];
      let usedList = JSON.parse(redeem.used_list);
      if (usedList.includes(user.username)) return json(res, { error: '已使用过' }, 400);
      await pool.query('UPDATE users SET points = points + $1 WHERE id = $2', [redeem.points, user.id]);
      usedList.push(user.username);
      await pool.query('UPDATE redeem_codes SET used_list = $1 WHERE code = $2', [JSON.stringify(usedList), code]);
      return json(res, { success: true, pointsAdded: redeem.points });
    }

    // 商品列表
    if (url === '/api/shop/items') {
      const items = await pool.query('SELECT * FROM shop_items ORDER BY id');
      return json(res, items.rows);
    }

    // 购买商品
    if (url === '/api/shop/buy' && method === 'POST') {
      const user = verifyToken(req);
      if (!user) return json(res, { error: '未登录' }, 401);
      const { itemId } = req.body;
      const itemRes = await pool.query('SELECT * FROM shop_items WHERE id = $1', [itemId]);
      if (itemRes.rows.length === 0) return json(res, { error: '商品不存在' }, 404);
      const item = itemRes.rows[0];
      if (item.stock <= 0) return json(res, { error: '已售罄' }, 400);
      const userPointsRes = await pool.query('SELECT points FROM users WHERE id = $1', [user.id]);
      if (userPointsRes.rows[0].points < item.price) return json(res, { error: '积分不足' }, 400);
      await pool.query('UPDATE users SET points = points - $1 WHERE id = $2', [item.price, user.id]);
      await pool.query('UPDATE shop_items SET stock = stock - 1 WHERE id = $1', [itemId]);
      return json(res, { success: true });
    }

    // 聊天消息
    if (url === '/api/chat/messages') {
      const msgs = await pool.query('SELECT username, avatar, content, timestamp, is_admin, is_vip, title FROM chat_messages ORDER BY id DESC LIMIT 100');
      return json(res, msgs.rows.reverse());
    }

    // 发送消息
    if (url === '/api/chat/send' && method === 'POST') {
      const user = verifyToken(req);
      if (!user) return json(res, { error: '未登录' }, 401);
      const { content } = req.body;
      if (!content || content.trim().length === 0) return json(res, { error: '内容不能为空' }, 400);
      const dbUser = await pool.query('SELECT username, avatar, is_vip, is_admin, title FROM users WHERE id = $1', [user.id]);
      const u = dbUser.rows[0];
      const timestamp = new Date().toISOString();
      await pool.query('INSERT INTO chat_messages (username, avatar, content, timestamp, is_admin, is_vip, title) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [u.username, u.avatar, content, timestamp, u.is_admin, u.is_vip, u.title]);
      return json(res, { success: true });
    }

    // 团队
    if (url === '/api/team') {
      const team = await pool.query('SELECT name, role, avatar FROM team_members');
      return json(res, team.rows);
    }

    // 在线心跳
    if (url === '/api/online/heartbeat' && method === 'POST') {
      const user = verifyToken(req);
      if (!user) return json(res, { error: '未登录' }, 401);
      const now = Math.floor(Date.now() / 1000);
      await pool.query('INSERT INTO online_users (username, last_seen) VALUES ($1, $2) ON CONFLICT (username) DO UPDATE SET last_seen = $2', [user.username, now]);
      return json(res, { success: true });
    }
    if (url === '/api/online/count') {
      const expire = Math.floor(Date.now() / 1000) - 300;
      const countRes = await pool.query('SELECT COUNT(*) as count FROM online_users WHERE last_seen > $1', [expire]);
      return json(res, { count: parseInt(countRes.rows[0].count) });
    }

    // 管理员接口
    if (url === '/api/admin/users' && method === 'GET') {
      const user = verifyToken(req);
      if (!user || !user.isAdmin) return json(res, { error: '无权限' }, 403);
      const users = await pool.query('SELECT id, username, points, is_vip, is_admin, reg_date FROM users');
      return json(res, users.rows);
    }
    if (url === '/api/admin/set-vip' && method === 'POST') {
      const user = verifyToken(req);
      if (!user || !user.isAdmin) return json(res, { error: '无权限' }, 403);
      const { username, isVip } = req.body;
      await pool.query('UPDATE users SET is_vip = $1 WHERE username = $2', [isVip ? 1 : 0, username]);
      return json(res, { success: true });
    }
    if (url === '/api/admin/set-admin' && method === 'POST') {
      const user = verifyToken(req);
      if (!user || !user.isAdmin) return json(res, { error: '无权限' }, 403);
      const { username, isAdmin } = req.body;
      await pool.query('UPDATE users SET is_admin = $1 WHERE username = $2', [isAdmin ? 1 : 0, username]);
      return json(res, { success: true });
    }
    if (url === '/api/admin/generate-redeem' && method === 'POST') {
      const user = verifyToken(req);
      if (!user || !user.isAdmin) return json(res, { error: '无权限' }, 403);
      const { code, points } = req.body;
      try {
        await pool.query('INSERT INTO redeem_codes (code, points, used_list) VALUES ($1, $2, $3)', [code, points, '[]']);
        return json(res, { success: true });
      } catch (e) {
        return json(res, { error: '兑换码已存在' }, 400);
      }
    }
    if (url === '/api/admin/add-shop-item' && method === 'POST') {
      const user = verifyToken(req);
      if (!user || !user.isAdmin) return json(res, { error: '无权限' }, 403);
      const { name, description, price, stock } = req.body;
      await pool.query('INSERT INTO shop_items (name, description, price, stock) VALUES ($1, $2, $3, $4)', [name, description, price, stock]);
      return json(res, { success: true });
    }
    if (url === '/api/admin/delete-shop-item' && method === 'POST') {
      const user = verifyToken(req);
      if (!user || !user.isAdmin) return json(res, { error: '无权限' }, 403);
      const { id } = req.body;
      await pool.query('DELETE FROM shop_items WHERE id = $1', [id]);
      return json(res, { success: true });
    }
    if (url === '/api/admin/maintenance' && method === 'GET') {
      const user = verifyToken(req);
      if (!user || !user.isAdmin) return json(res, { error: '无权限' }, 403);
      const row = await pool.query('SELECT value FROM site_config WHERE key = $1', ['maintenance']);
      return json(res, { enabled: row.rows[0]?.value === 'true' });
    }
    if (url === '/api/admin/maintenance' && method === 'POST') {
      const user = verifyToken(req);
      if (!user || !user.isAdmin) return json(res, { error: '无权限' }, 403);
      const { enabled } = req.body;
      await pool.query('UPDATE site_config SET value = $1 WHERE key = $2', [enabled ? 'true' : 'false', 'maintenance']);
      return json(res, { success: true });
    }

    return json(res, { error: 'Not found' }, 404);
  } catch (err) {
    console.error(err);
    return json(res, { error: '服务器内部错误' }, 500);
  }
};