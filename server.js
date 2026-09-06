require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const radius = require('radius');
const dgram = require('dgram');
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
const redis = require('redis');

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'authen_logs',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const pool_comcenter = mysql.createPool({
  host: process.env.DB_COMCENTER_HOST,
  user: process.env.DB_COMCENTER_USER,
  password: process.env.DB_COMCENTER_PASSWORD,
  database: "teamcom3_pis",
  charset: 'tis620',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const redisClient = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: process.env.REDIS_PORT || 6379,
    keepAlive: 5000,
    reconnectStrategy: (retries) => Math.min(retries * 100, 3000)
  },
  password: process.env.REDIS_PASS || undefined
});
redisClient.on('error', (err) => console.error('❌ Redis Client Error:', err.message));
redisClient.on('reconnecting', () => console.log('🔄 Redis reconnecting...'));
redisClient.on('ready', () => console.log('✅ Redis connected and ready'));
redisClient.connect().catch((err) => console.error('❌ Redis initial connect failed:', err.message));

const RADIUS_SECRET = process.env.RADIUS_SECRET;
const RADIUS_SERVER = process.env.RADIUS_SERVER;
const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_EXP = process.env.TOKEN_EXP || '24h';


async function saveLoginLog(username, ip, userAgent, status, errorMessage = null, subdomain = null) {
  try {
    const query = `
      INSERT INTO authen_logs (username, ip_address, subdomain, user_agent, status, error_message)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    await pool.execute(query, [username, ip, subdomain, userAgent, status, errorMessage]);
  } catch (err) {
    console.error('❌ Database Log Error:', err.message);
  }
}


async function sendMophAlert(cid, text, html, appPushText) {
  try {
    const safeCid = String(cid).trim();
    const payload = {
      cid: [safeCid],
      messages: [{ text: text, type: "text" }],
      message_title: "แจ้งเตือนการเข้าสู่ระบบ RBH",
      message_html: html,
      message_text: appPushText,
      message_type: "HPT"
    };

    const response = await fetch(process.env.MOPH_API_URL, {
      method: 'POST',
      headers: {
        'client-key': process.env.MOPH_CLIENT_KEY,
        'secret-key': process.env.MOPH_SECRET_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(8000)
    });

    const responseText = await response.text();
    let data = {};
    try {
      data = JSON.parse(responseText);
    } catch (parseErr) {
      console.error(`⚠️ MOPH Alert API returned non-JSON [HTTP ${response.status}]:`, responseText.substring(0, 250));
      return { success: false, data: {} };
    }

    console.log(`📬 MOPH Alert Response [CID: ${safeCid}]:`, JSON.stringify(data));
    return { success: response.ok, data };
  } catch (err) {
    console.error('❌ MOPH Alert failed:', err.message);
    return { success: false, data: {} };
  }
}

// ====================
// Login Page (Modern Blue & Deep Navy - Perfectly Centered Grid)
// ====================
function renderOtpPage(res, token, decoded, errorMessage = '', successMessage = '') {
  try {
    const templatePath = path.join(__dirname, 'views', 'otp.html');
    let html = fs.readFileSync(templatePath, 'utf8');

    if (decoded.noMoph) {
      const blockedHtml = `
        <h2>ไม่สามารถเข้าสู่ระบบได้</h2>
        <div class="user-info">ชื่อผู้ใช้งาน: <strong>${decoded.fullname || decoded.user}</strong></div>
        <div class="error-box">
          ไม่สามารถส่ง OTP ไปยัง Line หมอพร้อมได้ กรุณา Add line หมอพร้อมและ Login ให้เรียบร้อย
        </div>
        <a href="/rbhlogin" class="btn-back">กลับไปหน้าเข้าสู่ระบบ</a>
      `;
      html = html.replace('{{blockedView}}', blockedHtml);
      html = html.replace('{{otpFormView}}', '');
    } else {
      html = html.replace('{{blockedView}}', '');

      let errorHtml = errorMessage ? `<div class="error-box">${errorMessage}</div>` : '';
      let successHtml = successMessage ? `<div class="success-box">${successMessage}</div>` : '';

      const formHtml = `
        <h2>ยืนยันรหัส OTP</h2>
        <div class="subtitle">ระบบได้ส่งรหัส OTP ไปยังหมอพร้อมของท่านแล้ว</div>
        
        <div class="ref-badge">
          รหัสอ้างอิง (Ref): <strong>${decoded.ref}</strong>
        </div>

        <div class="user-info">ผู้ใช้งาน: <strong>${decoded.fullname || decoded.user}</strong></div>

        ${errorHtml}
        ${successHtml}

        <form id="otpForm" method="post" action="/rbhlogin">
          <input type="hidden" name="action" value="otp-verify">
          <input type="hidden" name="token" value="${token}">
          <input type="hidden" id="fullOtpInput" name="otp" value="">

          <div class="otp-inputs">
            <input type="text" inputmode="numeric" maxlength="1" class="otp-digit" pattern="[0-9]" required autocomplete="off" />
            <input type="text" inputmode="numeric" maxlength="1" class="otp-digit" pattern="[0-9]" required autocomplete="off" />
            <input type="text" inputmode="numeric" maxlength="1" class="otp-digit" pattern="[0-9]" required autocomplete="off" />
            <input type="text" inputmode="numeric" maxlength="1" class="otp-digit" pattern="[0-9]" required autocomplete="off" />
            <input type="text" inputmode="numeric" maxlength="1" class="otp-digit" pattern="[0-9]" required autocomplete="off" />
            <input type="text" inputmode="numeric" maxlength="1" class="otp-digit" pattern="[0-9]" required autocomplete="off" />
          </div>

          <button type="submit" class="btn-submit">ยืนยันรหัส OTP</button>
        </form>

        <form method="post" action="/rbhlogin">
          <input type="hidden" name="action" value="otp-resend">
          <input type="hidden" name="token" value="${token}">
          <button type="submit" id="resendBtn" class="btn-resend" disabled>
            ขอรหัส OTP อีกครั้ง<span id="resendTimer"> (60s)</span>
          </button>
        </form>
      `;
      html = html.replace('{{otpFormView}}', formHtml);
    }

    return res.send(html);
  } catch (err) {
    console.error('Error rendering OTP page:', err);
    return res.redirect('/rbhlogin?error=failed');
  }
}

// ====================
// Login Page & OTP Verification Page
// ====================
app.get(['/rbhlogin', '/rbhlogin/otp'], (req, res) => {
  if (req.query.action === 'otp-status' || req.path === '/rbhlogin/otp') {
    const token = req.query.token;
    if (!token) return res.redirect('/rbhlogin');

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const successMsg = req.query.resend === 'success' ? 'ส่งรหัส OTP ใหม่ไปยังหมอพร้อมแล้ว' : '';
      return renderOtpPage(res, token, decoded, '', successMsg);
    } catch (err) {
      return res.redirect('/rbhlogin?error=failed');
    }
  }

  const redirect = req.query.redirect || '/';
  const errorType = req.query.error; // ดึงประเภทของ error มาเช็ค
  
  // สร้างข้อความแจ้งเตือนตามความเหมาะสม
  let errorMessage = '';
  if (errorType === 'failed') {
    errorMessage = '<div class="error">เข้าสู่ระบบไม่สำเร็จ กรุณาตรวจสอบ Username และ Password ของ RBH CONNEXT</div>';
  } else if (errorType === 'locked') {
    errorMessage = '<div class="error">ระงับการใช้งานชั่วคราว! เนื่องจากลองรหัสผ่านผิดเกินกำหนด (กรุณารอ 15 นาที)</div>';
  } else if (errorType === 'inactive') {
    errorMessage = '<div class="error">User นี้ถูกระงับการใช้งาน</div>';
  }

  try {
    const templatePath = path.join(__dirname, 'views', 'login.html');
    let html = fs.readFileSync(templatePath, 'utf8');
    
    html = html.replace('{{errorMessage}}', errorMessage);
    html = html.replace('{{redirect}}', encodeURIComponent(redirect));
    html = html.replace('{{year}}', (new Date()).getFullYear());
    
    res.send(html);
  } catch (error) {
    console.error('Error reading HTML template:', error);
    res.status(500).send('Internal Server Error');
  }
});

// ====================
// Login Handler (RADIUS & OTP verify/resend)
// ====================
app.post(['/rbhlogin', '/rbhlogin/otp'], async (req, res) => {
  let ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (ipAddress && ipAddress.includes(',')) {
    ipAddress = ipAddress.split(',')[0].trim();
  }
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const host = req.headers['x-original-host'] || req.headers.host || '';
  const subdomain = host.split('.')[0] || null;

  // Case 1: OTP Verification
  if (req.body.action === 'otp-verify') {
    const { token, otp } = req.body;
    if (!token) return res.redirect('/rbhlogin');

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.noMoph) return res.redirect('/rbhlogin');

      let cachedOtp = null;
      try {
        if (redisClient.isOpen) {
          cachedOtp = await redisClient.get(`otp:${decoded.user}`);
        }
      } catch (redisErr) {
        console.error('Redis get error:', redisErr.message);
      }

      if (!cachedOtp || String(cachedOtp).trim() !== String(otp).trim()) {
        await saveLoginLog(decoded.user, ipAddress, userAgent, 'FAILED', 'Invalid or expired OTP', subdomain);
        return renderOtpPage(res, token, decoded, 'รหัส OTP ไม่ถูกต้องหรือหมดอายุ');
      }

      // Correct OTP -> Delete from Redis
      try {
        if (redisClient.isOpen) {
          await redisClient.del(`otp:${decoded.user}`);
        }
      } catch (delErr) {
        console.error('Redis del error:', delErr.message);
      }

      // Log to DB
      await saveLoginLog(decoded.user, ipAddress, userAgent, 'SUCCESS', null, subdomain);
      
      // Issue real token
      const realToken = jwt.sign({ user: decoded.user }, JWT_SECRET, { expiresIn: TOKEN_EXP });
      res.cookie('rbh-auth', realToken, { 
        httpOnly: true,
        domain: process.env.COOKIE_DOMAIN || '.rajburi.org', 
        secure: true,           
        sameSite: 'lax'         
      });
      
      return res.redirect(decoded.redirect || '/');
    } catch (err) {
      return res.redirect('/rbhlogin?error=failed');
    }
  }

  // Case 2: OTP Resend
  if (req.body.action === 'otp-resend') {
    const { token } = req.body;
    if (!token) return res.redirect('/rbhlogin');

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.noMoph) return res.redirect('/rbhlogin');

      const newOtp = Math.floor(100000 + Math.random() * 900000).toString(); // 6 digits
      const newRef = Math.random().toString(36).substring(2, 8).toUpperCase(); // 6 chars

      try {
        if (redisClient.isOpen) {
          await redisClient.setEx(`otp:${decoded.user}`, 300, newOtp); // 5 mins
        }
      } catch (redisErr) {
        console.error('Redis setEx error:', redisErr.message);
      }

      if (decoded.cid) {
        const msgText = `รหัส OTP ของคุณคือ ${newOtp}\n(Ref: ${newRef})\nRatchaburi Hospital`;
        const msgHtml = `<div>รหัส OTP ของคุณคือ <b>${newOtp}</b><br>Ref: ${newRef}<br></div>`;
        const appPushText = `รหัส OTP ของคุณคือ ${newOtp}`;
        await sendMophAlert(decoded.cid, msgText, msgHtml, appPushText);
        await saveLoginLog(decoded.user, ipAddress, userAgent, 'OTP_SENT', 'OTP resent', subdomain);
      }

      const newTempToken = jwt.sign({
        user: decoded.user,
        fullname: decoded.fullname,
        has_line_rbh: decoded.has_line_rbh,
        has_moph_app: decoded.has_moph_app,
        has_moph_line: decoded.has_moph_line,
        cid: decoded.cid,
        noMoph: false,
        ref: newRef,
        redirect: decoded.redirect
      }, JWT_SECRET, { expiresIn: '5m' });

      return res.redirect(`/rbhlogin?action=otp-status&token=${newTempToken}&resend=success`);
    } catch (err) {
      return res.redirect('/rbhlogin?error=failed');
    }
  }

  // Case 3: Initial RADIUS Username & Password verification
  const { username, password, redirect: bodyRedirect } = req.body;
  const redirect = bodyRedirect || req.query.redirect || '/';
  
  const MAX_FAILED_ATTEMPTS = parseInt(process.env.MAX_FAILED_ATTEMPTS) || 5;
  const LOCK_WINDOW_MINUTES = parseInt(process.env.LOCK_WINDOW_MINUTES) || 15;

  try {
    // 1. ตรวจสอบสถานะการโดนแบนจากฐานข้อมูล
    const checkQuery = `
      SELECT COUNT(*) AS fail_count 
      FROM authen_logs 
      WHERE ip_address = ? 
        AND status = 'FAILED' 
        AND created_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)
    `;
    const [rows] = await pool.execute(checkQuery, [ipAddress, LOCK_WINDOW_MINUTES]);
    const failCount = rows[0].fail_count;

    if (failCount >= MAX_FAILED_ATTEMPTS) {
      await saveLoginLog(username, ipAddress, userAgent, 'LOCKED', 'IP is blocked due to excessive failed attempts', subdomain);
      return res.redirect(`/rbhlogin?error=locked&redirect=${encodeURIComponent(redirect)}`);
    }

    // 2. ส่ง Request ตรวจสอบสิทธิ์กับ RADIUS Server
    const isAuthenticated = await new Promise((resolve, reject) => {
      const packet = radius.encode({
        code: 'Access-Request',
        secret: RADIUS_SECRET,
        attributes: [
          ['NAS-IP-Address', '10.10.90.10'],
          ['User-Name', username],
          ['User-Password', password]
        ]
      });

      const client = dgram.createSocket('udp4');
      
      const timeoutToken = setTimeout(() => {
        client.close();
        reject(new Error('RADIUS Server Timeout'));
      }, 5000);

      client.on('message', (msg) => {
        try {
          clearTimeout(timeoutToken);
          const response = radius.decode({ packet: msg, secret: RADIUS_SECRET });
          client.close();
          resolve(response.code === 'Access-Accept');
        } catch (e) {
          client.close();
          reject(e);
        }
      });

      client.on('error', (err) => {
        clearTimeout(timeoutToken);
        client.close();
        reject(err);
      });

      client.send(packet, 0, packet.length, 1812, RADIUS_SERVER, (err) => {
        if (err) {
          clearTimeout(timeoutToken);
          client.close();
          reject(err);
        }
      });
    });

    // 3. จัดการผลลัพธ์หลังจากได้ข้อมูลจาก RADIUS
    if (isAuthenticated) {
      // Query User Data
      let fullname = '', lineid = '', cid = '', isActive = false;
      try {
        const [userRows] = await pool_comcenter.execute('SELECT fullname, userId as lineid, cid, active FROM users WHERE username = ?', [username]);
        if (userRows.length > 0) {
          fullname = userRows[0].fullname;
          lineid = userRows[0].lineid;
          cid = userRows[0].cid;
          isActive = userRows[0].active === 1 || userRows[0].active === '1' || userRows[0].active === true;
        }
      } catch (err) {
        console.error('Error fetching user data:', err.message);
      }

      // Check if user is inactive (active != 1) or user not found
      if (!isActive) {
        await saveLoginLog(username, ipAddress, userAgent, 'INACTIVE', 'User is suspended/inactive (active != 1)', subdomain);
        return res.redirect(`/rbhlogin?error=inactive&redirect=${encodeURIComponent(redirect)}`);
      }


      // Generate OTP and Ref
      const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6 digits
      const ref = Math.random().toString(36).substring(2, 8).toUpperCase(); // 6 chars
      
      let has_moph_app = false;
      let has_moph_line = false;
      const has_line_rbh = !!lineid;

      if (cid) {
        const msgText = `รหัส OTP ของคุณคือ ${otp}\n(Ref: ${ref})\nRatchaburi Hospital`;
        const msgHtml = `<div>รหัส OTP ของคุณคือ <b>${otp}</b><br>Ref: ${ref}<br></div>`;
        const appPushText = `รหัส OTP ของคุณคือ ${otp} (Ref: ${ref})`;
        const alertRes = await sendMophAlert(cid, msgText, msgHtml, appPushText);
        if (alertRes.data) {
          const appMsg = (alertRes.data.app_message || '').toLowerCase();
          const lineMsg = (alertRes.data.line_message || '').toLowerCase();
          has_moph_app = appMsg.includes('success');
          has_moph_line = lineMsg.includes('success');
        }
      }

      // ตรวจสอบว่ามีอย่างใดอย่างหนึ่ง (App หมอพร้อม หรือ Line หมอพร้อม)
      const hasMoph = has_moph_app || has_moph_line;
      const noMoph = !cid || !hasMoph;

      if (noMoph) {
        await saveLoginLog(username, ipAddress, userAgent, 'NO_MOPH', 'No MOPH App/Line', subdomain);
      } else {
        const mophDetails = `OTP sent (App: ${has_moph_app ? 'Yes' : 'No'}, Line: ${has_moph_line ? 'Yes' : 'No'})`;
        await saveLoginLog(username, ipAddress, userAgent, 'OTP_SENT', mophDetails, subdomain);
        try {
          if (redisClient.isOpen) {
            await redisClient.setEx(`otp:${username}`, 300, otp); // 5 mins
          }
        } catch (redisErr) {
          console.error('❌ Redis setEx error:', redisErr.message);
        }
      }

      // Issue temporary token to pass state to the OTP verification screen
      const tempToken = jwt.sign({ 
        user: username, 
        fullname, 
        has_line_rbh, 
        has_moph_app, 
        has_moph_line,
        cid,
        noMoph,
        ref,
        redirect 
      }, JWT_SECRET, { expiresIn: '5m' });
      
      return res.redirect(`/rbhlogin?action=otp-status&token=${tempToken}`);
      
    } else {
      const remainingAttempts = MAX_FAILED_ATTEMPTS - (failCount + 1);
      await saveLoginLog(username, ipAddress, userAgent, 'FAILED', 'RADIUS Access-Reject', subdomain);
      
      if (remainingAttempts <= 0) {
        return res.redirect(`/rbhlogin?error=locked&redirect=${encodeURIComponent(redirect)}`);
      } else {
        return res.redirect(`/rbhlogin?error=failed&redirect=${encodeURIComponent(redirect)}`);
      }
    }

  } catch (error) {
    console.error('Auth Flow Error:', error);
    await saveLoginLog(username, ipAddress, userAgent, 'FAILED', `System error: ${error.message}`, subdomain);
    return res.redirect(`/rbhlogin?error=failed&redirect=${encodeURIComponent(redirect)}`);
  }
});



// ====================
// Verify Token (สำหรับ Nginx /auth)
// ====================
app.get('/verify', (req, res) => {
  const token = req.cookies['rbh-auth'] || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).send('No token');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.status(200).send('OK');
  } catch (err) {
    res.status(401).send('Invalid token');
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Auth server listening on port ${PORT}`));