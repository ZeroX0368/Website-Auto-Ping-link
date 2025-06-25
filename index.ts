
import * as http from "http";
import fetch from "node-fetch";
import * as fs from "fs";
import * as crypto from "crypto";

const port = 3000;
const hostname = "0.0.0.0";

interface PingTarget {
  url: string;
  lastPing?: Date;
  status?: string;
}

interface User {
  id: string;
  username: string;
  password: string; // In production, this should be hashed
  pingTargets: PingTarget[];
  lastLogin: Date;
}

interface Session {
  userId: string;
  expires: Date;
}

let users: User[] = [];
let sessions: { [sessionId: string]: Session } = {};

// Load users from file
function loadUsers() {
  try {
    if (fs.existsSync('users.json')) {
      const data = fs.readFileSync('users.json', 'utf8');
      users = JSON.parse(data);
    }
  } catch (error) {
    console.log('Could not load users file, starting fresh');
    users = [];
  }
}

// Save users to file
function saveUsers() {
  try {
    fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
  } catch (error) {
    console.error('Could not save users file:', error);
  }
}

// Initialize users
loadUsers();

// Function to clean up inactive accounts (older than 2 days)
function cleanupInactiveAccounts() {
  const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
  const initialCount = users.length;
  
  users = users.filter(user => {
    const lastLogin = user.lastLogin ? new Date(user.lastLogin) : new Date(0);
    return lastLogin > twoDaysAgo;
  });
  
  const deletedCount = initialCount - users.length;
  if (deletedCount > 0) {
    console.log(`[${new Date().toISOString()}] Deleted ${deletedCount} inactive accounts`);
    saveUsers();
    
    // Clean up sessions for deleted users
    Object.keys(sessions).forEach(sessionId => {
      const session = sessions[sessionId];
      const userExists = users.find(u => u.id === session.userId);
      if (!userExists) {
        delete sessions[sessionId];
      }
    });
  }
}

// Run cleanup every hour
setInterval(cleanupInactiveAccounts, 60 * 60 * 1000);

// Initialize users

// Function to ping a URL
async function pingUrl(url: string): Promise<{ status: string; responseTime: number }> {
  const startTime = Date.now();
  try {
    const response = await fetch(url, {
      method: 'GET',
      timeout: 10000,
    });
    const responseTime = Date.now() - startTime;
    return {
      status: `${response.status} ${response.statusText}`,
      responseTime
    };
  } catch (error) {
    const responseTime = Date.now() - startTime;
    return {
      status: `Error: ${error.message}`,
      responseTime
    };
  }
}

// Function to ping all URLs for all users
async function pingAllUrls() {
  console.log(`[${new Date().toISOString()}] Starting ping cycle...`);
  
  for (const user of users) {
    for (const target of user.pingTargets) {
      try {
        const result = await pingUrl(target.url);
        target.lastPing = new Date();
        target.status = `${result.status} (${result.responseTime}ms)`;
        console.log(`Pinged ${target.url} for user ${user.username}: ${target.status}`);
      } catch (error) {
        target.status = `Failed: ${error.message}`;
        console.log(`Failed to ping ${target.url} for user ${user.username}: ${target.status}`);
      }
    }
  }
  
  // Save updated ping data
  saveUsers();
}

// Start ping interval (every 3 seconds)
setInterval(pingAllUrls, 3 * 1000);

// Helper functions
function generateSessionId(): string {
  return crypto.randomBytes(32).toString('hex');
}

function isValidSession(sessionId: string): User | null {
  const session = sessions[sessionId];
  if (!session || session.expires < new Date()) {
    delete sessions[sessionId];
    return null;
  }
  return users.find(u => u.id === session.userId) || null;
}

function hashPassword(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex');
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const cookies = parseCookies(req.headers.cookie || '');
  const currentUser = cookies.sessionId ? isValidSession(cookies.sessionId) : null;

  res.setHeader("Content-Type", "text/html; charset=utf-8");

  // Register endpoint
  if (req.method === 'POST' && url.pathname === '/register') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const username = params.get('username');
      const password = params.get('password');

      if (!username || !password) {
        res.statusCode = 400;
        res.end(getAuthPage('Vui lòng điền đầy đủ thông tin!'));
        return;
      }

      if (users.find(u => u.username === username)) {
        res.statusCode = 400;
        res.end(getAuthPage('Tên đăng nhập đã tồn tại!'));
        return;
      }

      const newUser: User = {
        id: crypto.randomUUID(),
        username,
        password: hashPassword(password),
        pingTargets: [],
        lastLogin: new Date()
      };

      users.push(newUser);
      saveUsers();

      // Create session
      const sessionId = generateSessionId();
      sessions[sessionId] = {
        userId: newUser.id,
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
      };

      res.setHeader('Set-Cookie', `sessionId=${sessionId}; HttpOnly; Max-Age=86400`);
      res.writeHead(302, { Location: '/' });
      res.end();
    });
    return;
  }

  // Login endpoint
  if (req.method === 'POST' && url.pathname === '/login') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const username = params.get('username');
      const password = params.get('password');

      const user = users.find(u => u.username === username && u.password === hashPassword(password || ''));

      if (!user) {
        res.statusCode = 400;
        res.end(getAuthPage('Tên đăng nhập hoặc mật khẩu không đúng!'));
        return;
      }

      // Update last login time
      user.lastLogin = new Date();
      saveUsers();

      // Create session
      const sessionId = generateSessionId();
      sessions[sessionId] = {
        userId: user.id,
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000)
      };

      res.setHeader('Set-Cookie', `sessionId=${sessionId}; HttpOnly; Max-Age=86400`);
      res.writeHead(302, { Location: '/' });
      res.end();
    });
    return;
  }

  // Logout endpoint
  if (req.method === 'POST' && url.pathname === '/logout') {
    if (cookies.sessionId) {
      delete sessions[cookies.sessionId];
    }
    res.setHeader('Set-Cookie', 'sessionId=; HttpOnly; Max-Age=0');
    res.writeHead(302, { Location: '/' });
    res.end();
    return;
  }

  // Protected endpoints - require authentication
  if (!currentUser) {
    res.statusCode = 200;
    res.end(getAuthPage());
    return;
  }

  // Add URL endpoint
  if (req.method === 'POST' && url.pathname === '/add') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const newUrl = params.get('url');

      if (newUrl && (newUrl.startsWith('http://') || newUrl.startsWith('https://'))) {
        const exists = currentUser.pingTargets.find(target => target.url === newUrl);
        if (!exists) {
          currentUser.pingTargets.push({ url: newUrl, status: 'Chưa ping' });
          saveUsers();
        }
      }

      res.writeHead(302, { Location: '/' });
      res.end();
    });
    return;
  }

  // Remove URL endpoint
  if (req.method === 'POST' && url.pathname === '/remove') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const urlToRemove = params.get('url');

      if (urlToRemove) {
        currentUser.pingTargets = currentUser.pingTargets.filter(target => target.url !== urlToRemove);
        saveUsers();
      }

      res.writeHead(302, { Location: '/' });
      res.end();
    });
    return;
  }

  // Ping now endpoint
  if (req.method === 'POST' && url.pathname === '/ping-now') {
    (async () => {
      for (const target of currentUser.pingTargets) {
        try {
          const result = await pingUrl(target.url);
          target.lastPing = new Date();
          target.status = `${result.status} (${result.responseTime}ms)`;
        } catch (error) {
          target.status = `Failed: ${error.message}`;
        }
      }
      saveUsers();
      res.writeHead(302, { Location: '/' });
      res.end();
    })();
    return;
  }

  // Main dashboard
  res.statusCode = 200;
  res.end(getDashboard(currentUser));
});

function parseCookies(cookieHeader: string): { [key: string]: string } {
  const cookies: { [key: string]: string } = {};
  cookieHeader.split(';').forEach(cookie => {
    const [name, value] = cookie.trim().split('=');
    if (name && value) {
      cookies[name] = value;
    }
  });
  return cookies;
}

function getAuthPage(error?: string): string {
  return `
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Đăng nhập - Auto Ping</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 400px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { text-align: center; color: #333; }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-bottom: 10px;
        }
        button:hover { background: #0056b3; }
        .toggle-form {
            text-align: center;
            margin-top: 20px;
        }
        .toggle-form a {
            color: #007bff;
            text-decoration: none;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Auto Ping Service</h1>
        
        ${error ? `<div class="error">${error}</div>` : ''}

        <div id="loginForm">
            <h2>Đăng nhập</h2>
            <form method="POST" action="/login">
                <div class="form-group">
                    <label>Tên đăng nhập:</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>Mật khẩu:</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit">Đăng nhập</button>
            </form>
            <div class="toggle-form">
                <a href="#" onclick="toggleForm()">Chưa có tài khoản? Đăng ký ngay</a>
            </div>
        </div>

        <div id="registerForm" style="display:none;">
            <h2>Đăng ký</h2>
            <form method="POST" action="/register">
                <div class="form-group">
                    <label>Tên đăng nhập:</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>Mật khẩu:</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit">Đăng ký</button>
            </form>
            <div class="toggle-form">
                <a href="#" onclick="toggleForm()">Đã có tài khoản? Đăng nhập</a>
            </div>
        </div>
    </div>

    <script>
        function toggleForm() {
            const loginForm = document.getElementById('loginForm');
            const registerForm = document.getElementById('registerForm');
            
            if (loginForm.style.display === 'none') {
                loginForm.style.display = 'block';
                registerForm.style.display = 'none';
            } else {
                loginForm.style.display = 'none';
                registerForm.style.display = 'block';
            }
        }
    </script>
</body>
</html>
  `;
}

function getDashboard(user: User): string {
  return `
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auto Ping Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        h1 { color: #333; margin: 0; }
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .logout-btn {
            background: #dc3545;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
        }
        .add-form {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }
        input[type="url"] {
            width: 70%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        button {
            padding: 10px 20px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover { background: #0056b3; }
        .ping-list { list-style: none; padding: 0; }
        .ping-item {
            background: #f8f9fa;
            margin: 10px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }
        .url {
            font-weight: bold;
            color: #007bff;
            margin-bottom: 5px;
        }
        .status { color: #666; font-size: 14px; }
        .last-ping { color: #999; font-size: 12px; }
        .remove-btn {
            background: #dc3545;
            font-size: 12px;
            padding: 5px 10px;
            float: right;
        }
        .ping-now-btn {
            background: #28a745;
            margin-left: 10px;
        }
        .info {
            background: #e7f3ff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #007bff;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Auto Ping Dashboard</h1>
            <div class="user-info">
                <span>Xin chào, <strong>${user.username}</strong>!</span>
                <form method="POST" action="/logout" style="display: inline;">
                    <button type="submit" class="logout-btn">Đăng xuất</button>
                </form>
            </div>
        </div>
        
        <div class="info">
            <strong>ℹ️ Thông tin:</strong> Website sẽ tự động ping tất cả URL của bạn mỗi 3 giây. 
            URL của bạn sẽ được lưu trữ an toàn và không bị mất khi đăng xuất.<br>
            <strong>⚠️ Lưu ý:</strong> Tài khoản không đăng nhập trong 2 ngày sẽ bị xóa tự động.
        </div>

        <div class="add-form">
            <h3>Thêm URL mới</h3>
            <form method="POST" action="/add">
                <input type="url" name="url" placeholder="https://example.com" required>
                <button type="submit">Thêm URL</button>
                <form method="POST" action="/ping-now" style="display: inline;">
                    <button type="submit" class="ping-now-btn">Ping Ngay</button>
                </form>
            </form>
        </div>

        <h3>Danh sách URL của bạn (${user.pingTargets.length})</h3>
        
        ${user.pingTargets.length === 0 ? 
            '<p style="text-align: center; color: #666;">Chưa có URL nào. Thêm URL đầu tiên!</p>' :
            `<ul class="ping-list">
                ${user.pingTargets.map(target => `
                    <li class="ping-item">
                        <form method="POST" action="/remove" style="display: inline;">
                            <input type="hidden" name="url" value="${target.url}">
                            <button type="submit" class="remove-btn">Xóa</button>
                        </form>
                        <div class="url">${target.url}</div>
                        <div class="status">Trạng thái: ${target.status || 'Chưa ping'}</div>
                        ${target.lastPing ? 
                            `<div class="last-ping">Lần ping cuối: ${new Date(target.lastPing).toLocaleString('vi-VN')}</div>` : 
                            '<div class="last-ping">Chưa ping lần nào</div>'
                        }
                    </li>
                `).join('')}
            </ul>`
        }
        
        <div style="margin-top: 30px; text-align: center; color: #666; font-size: 14px;">
            <p>⏰ Tự động ping mỗi 3 giây | 🕐 Lần ping tiếp theo: ${new Date(Date.now() + 3 * 1000).toLocaleTimeString('vi-VN')}</p>
        </div>
    </div>

    <script>
        // Auto refresh page every 30 seconds to show updated status
        setTimeout(() => {
            window.location.reload();
        }, 30000);
    </script>
</body>
</html>
  `;
}

server.listen(port, hostname, () => {
  console.log(`🚀 Auto Ping Server running at http://${hostname}:${port}/`);
  console.log("📝 Users can register/login to save their URLs permanently");
});
