require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
const path = require('path');
const { MongoClient, ObjectId } = require('mongodb');
const { normalizeRequestBodyForUpstream, parseFormDataLines, formDataObjectToLines, formFilesToLines } = require('./requestBody');

const app = express();
const port = process.env.PORT || 3000;
const backendUrl = process.env.BACKEND_URL || `http://localhost:${port}`;
const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
const defaultAllowedOrigins = ['http://localhost:3000', 'http://localhost:5173', 'https://api-runner.onrender.com'];
const envAllowedOrigins = String(process.env.CORS_ORIGINS || '')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);
const allowedOrigins = [...new Set([...defaultAllowedOrigins, frontendUrl, ...envAllowedOrigins])];
const mongoUri = process.env.MONGO_URI;
const mongoDbName = process.env.MONGO_DB_NAME || 'api_tracker';
const hasGoogleOAuth =
  Boolean(process.env.GOOGLE_CLIENT_ID) &&
  Boolean(process.env.GOOGLE_CLIENT_SECRET) &&
  !process.env.GOOGLE_CLIENT_ID.includes('your_google_client_id_here') &&
  !process.env.GOOGLE_CLIENT_SECRET.includes('your_google_client_secret_here');
let mongoClient = null;
let usersCollection = null;
let projectsCollection = null;
let apisCollection = null;
let apiResponsesCollection = null;
let apiCurlsCollection = null;
let runHistoryCollection = null;

async function initDatabase() {
  if (!mongoUri) {
    console.log('DB: Not configured (set MONGO_URI)');
    return;
  }

  mongoClient = new MongoClient(mongoUri);
  await mongoClient.connect();

  const db = mongoClient.db(mongoDbName);
  usersCollection = db.collection('users');
  projectsCollection = db.collection('projects');
  apisCollection = db.collection('apis');
  apiResponsesCollection = db.collection('api_responses');
  apiCurlsCollection = db.collection('api_curls');
  runHistoryCollection = db.collection('run_history');

  await usersCollection.createIndex({ googleId: 1 }, { unique: true });
  await usersCollection.createIndex({ email: 1 }, { unique: true });
  await projectsCollection.createIndex({ user_id: 1, created_at: -1 });
  await apisCollection.createIndex({ project_id: 1, created_at: -1 });
  await apiResponsesCollection.createIndex({ api_id: 1, created_at: -1 });
  await apiCurlsCollection.createIndex({ api_id: 1, created_at: -1 });
  await runHistoryCollection.createIndex({ user_id: 1, created_at: -1 });

  console.log(`DB: Connected (MongoDB/${mongoDbName})`);
}

async function upsertUserInDatabase(user) {
  if (!usersCollection) return null;

  const now = new Date();
  await usersCollection.updateOne(
    { googleId: user.id },
    {
      $set: {
        googleId: user.id,
        name: user.name,
        email: user.email,
        picture: user.picture || null,
        updatedAt: now,
        lastLoginAt: now
      },
      $setOnInsert: {
        createdAt: now
      }
    },
    { upsert: true }
  );

  return usersCollection.findOne(
    { googleId: user.id },
    { projection: { _id: 1, googleId: 1, name: 1, email: 1, picture: 1, createdAt: 1, updatedAt: 1, lastLoginAt: 1 } }
  );
}

// Middleware
app.set('trust proxy', 1);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000
  } // 24h
}));
app.use(passport.initialize());
app.use(passport.session());

// Passport serialize/deserialize
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

if (hasGoogleOAuth) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${backendUrl}/auth/google/callback`
  }, async (accessToken, refreshToken, profile, done) => {
    const user = {
      id: profile.id,
      name: profile.displayName,
      email: profile.emails[0].value,
      picture: profile.photos[0].value
    };

    try {
      const dbUser = await upsertUserInDatabase(user);
      if (dbUser) {
        user.dbUserId = String(dbUser._id);
      }
    } catch (error) {
      console.error('Failed to save user in users table:', error.message);
    }

    return done(null, user);
  }));
}

// Auth Routes
app.get('/auth/google', (req, res, next) => {
  if (!hasGoogleOAuth) {
    return res.status(503).json({
      error: 'Google OAuth is not configured on the server'
    });
  }

  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

app.get('/auth/google/callback',
  (req, res, next) => {
    if (!hasGoogleOAuth) {
      return res.redirect(`${frontendUrl}/?error=oauth_not_configured`);
    }
    return passport.authenticate('google', { failureRedirect: `${frontendUrl}/?error=auth_failed` })(req, res, next);
  },
  (req, res) => {
    // Success - hand control back to frontend dashboard; user is restored from session.
    res.redirect(`${frontendUrl}/dashboard`);
  }
);

app.get('/api/auth-status', (req, res) => {
  res.json({ googleOAuthConfigured: hasGoogleOAuth });
});

app.get('/auth/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => {
      res.redirect(`${frontendUrl}/`);
    });
  });
});

app.get('/api/user', (req, res) => {
  if (req.user) {
    res.json(req.user);
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

function sanitizeHeaders(headers = {}) {
  const blocked = new Set(['host', 'connection', 'content-length', 'cookie']);
  const clean = {};

  for (const [key, value] of Object.entries(headers)) {
    if (!key) continue;
    const normalizedKey = String(key).trim().toLowerCase();
    if (!normalizedKey || blocked.has(normalizedKey)) continue;
    clean[normalizedKey] = String(value);
  }

  return clean;
}

function safeJsonParse(value, fallback = {}) {
  if (!value) return fallback;
  if (typeof value === 'object') return value;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function buildCurlCommandByMode({ method, url, headers = {}, body = '', bodyMode = 'raw' }) {
  const parts = [`curl -X ${method} "${url}"`];
  const normalizedBodyMode = bodyMode === 'form-data' ? 'form-data' : 'raw';
  const headerEntries = Object.entries(headers || {});

  if (normalizedBodyMode === 'form-data' && !['GET', 'HEAD'].includes(method)) {
    const cleanedHeaders = headerEntries.filter(([key]) => String(key).toLowerCase() !== 'content-type');
    cleanedHeaders.forEach(([key, value]) => {
      parts.push(`-H "${key}: ${String(value).replace(/"/g, '\\"')}"`);
    });
    const fields = parseFormDataLines(body);
    fields.forEach(([key, value]) => {
      parts.push(`-F "${String(key).replace(/"/g, '\\"')}=${String(value).replace(/"/g, '\\"')}"`);
    });
    return parts.join(' \\\n  ');
  }

  headerEntries.forEach(([key, value]) => {
    parts.push(`-H "${key}: ${String(value).replace(/"/g, '\\"')}"`);
  });
  if (!['GET', 'HEAD'].includes(method) && body) {
    parts.push(`--data '${String(body).replace(/'/g, "'\\''")}'`);
  }
  return parts.join(' \\\n  ');
}

async function executeUpstreamRequest(payload) {
  const {
    url,
    method = 'GET',
    headers = {},
    body = '',
    form_files = [],
    timeoutMs = 30000
  } = payload || {};

  if (!url) {
    return { statusCode: 400, error: 'url is required' };
  }

  let targetUrl;
  try {
    targetUrl = new URL(url);
  } catch {
    return { statusCode: 400, error: 'Invalid URL' };
  }

  if (!['http:', 'https:'].includes(targetUrl.protocol)) {
    return { statusCode: 400, error: 'Only http/https URLs are allowed' };
  }

  const normalizedMethod = String(method).toUpperCase();
  const allowedMethods = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
  if (!allowedMethods.has(normalizedMethod)) {
    return { statusCode: 400, error: `Unsupported method: ${normalizedMethod}` };
  }

  const controller = new AbortController();
  const boundedTimeout = Math.min(Math.max(Number(timeoutMs) || 30000, 1000), 120000);
  const timer = setTimeout(() => controller.abort(), boundedTimeout);

  try {
    const requestHeaders = sanitizeHeaders(headers);
    const bodyMode = payload?.body_mode === 'form-data' ? 'form-data' : 'raw';
    const requestInit = {
      method: normalizedMethod,
      headers: requestHeaders,
      signal: controller.signal
    };

    if (!['GET', 'HEAD'].includes(normalizedMethod) && body !== null && body !== undefined && body !== '') {
      const normalized = normalizeRequestBodyForUpstream({
        body,
        bodyMode,
        headers: requestHeaders,
        formFiles: form_files
      });
      requestInit.body = normalized.body;
      requestInit.headers = normalized.headers;
    }

    const startedAt = Date.now();
    const upstreamResponse = await fetch(targetUrl.toString(), requestInit);
    const durationMs = Date.now() - startedAt;
    const responseText = await upstreamResponse.text();

    const responseHeaders = {};
    upstreamResponse.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    let responseBody = responseText;
    const contentType = (upstreamResponse.headers.get('content-type') || '').toLowerCase();
    if (contentType.includes('application/json')) {
      try {
        responseBody = JSON.parse(responseText);
      } catch {
        responseBody = responseText;
      }
    }

    return {
      statusCode: 200,
      payload: {
        ok: upstreamResponse.ok,
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        durationMs,
        headers: responseHeaders,
        body: responseBody
      }
    };
  } catch (error) {
    const isTimeout = error.name === 'AbortError';
    return {
      statusCode: isTimeout ? 504 : 500,
      error: isTimeout ? 'Upstream request timed out' : 'Request failed',
      details: error.message
    };
  } finally {
    clearTimeout(timer);
  }
}

async function resolveCurrentUser(req) {
  if (!req.user || !usersCollection) return null;
  if (req.user.dbUserId) return req.user.dbUserId;

  const dbUser = await usersCollection.findOne({ googleId: req.user.id }, { projection: { _id: 1 } });
  return dbUser ? String(dbUser._id) : null;
}

async function ensureAuth(req, res, next) {
  try {
    const userId = await resolveCurrentUser(req);
    if (!userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    req.userId = userId;
    return next();
  } catch (error) {
    return res.status(500).json({ error: 'Auth resolution failed', details: error.message });
  }
}

function parseObjectId(id) {
  if (!ObjectId.isValid(id)) return null;
  return new ObjectId(id);
}

async function saveRunHistory(entry) {
  if (!runHistoryCollection) return;
  await runHistoryCollection.insertOne(entry);
}

async function saveApiResponse(entry) {
  if (!apiResponsesCollection) return;
  await apiResponsesCollection.insertOne(entry);
}

async function saveApiCurl(entry) {
  if (!apiCurlsCollection) return;
  await apiCurlsCollection.insertOne(entry);
}

app.get('/api/projects', ensureAuth, async (req, res) => {
  const projects = await projectsCollection
    .find({ user_id: req.userId })
    .sort({ created_at: -1 })
    .toArray();
  res.json(projects);
});

app.post('/api/projects', ensureAuth, async (req, res) => {
  const { name, description = '', base_url = '' } = req.body || {};
  if (!name || !String(name).trim()) {
    return res.status(400).json({ error: 'Project name is required' });
  }
  const now = new Date();
  const doc = {
    user_id: req.userId,
    name: String(name).trim(),
    description: String(description || '').trim(),
    base_url: String(base_url || '').trim(),
    created_at: now
  };
  const result = await projectsCollection.insertOne(doc);
  res.status(201).json({ ...doc, _id: result.insertedId });
});

app.delete('/api/projects/:projectId', ensureAuth, async (req, res) => {
  const { projectId } = req.params;
  const projectObjectId = parseObjectId(projectId);
  if (!projectObjectId) return res.status(400).json({ error: 'Invalid project id' });

  const project = await projectsCollection.findOne({ _id: projectObjectId, user_id: req.userId });
  if (!project) return res.status(404).json({ error: 'Project not found' });

  const projectApis = await apisCollection.find({ project_id: projectId, user_id: req.userId }).project({ _id: 1 }).toArray();
  const apiIds = projectApis.map((api) => String(api._id));

  await projectsCollection.deleteOne({ _id: projectObjectId, user_id: req.userId });
  await apisCollection.deleteMany({ project_id: projectId, user_id: req.userId });

  if (apiIds.length > 0) {
    await apiResponsesCollection.deleteMany({ api_id: { $in: apiIds }, user_id: req.userId });
    await apiCurlsCollection.deleteMany({ api_id: { $in: apiIds }, user_id: req.userId });
  }

  await runHistoryCollection.deleteMany({
    user_id: req.userId,
    $or: [
      { project_id: projectId },
      ...(apiIds.length > 0 ? [{ api_id: { $in: apiIds } }] : [])
    ]
  });

  res.json({ success: true, deleted_project_id: projectId });
});

app.get('/api/projects/:projectId/apis', ensureAuth, async (req, res) => {
  const { projectId } = req.params;
  const projectObjectId = parseObjectId(projectId);
  if (!projectObjectId) return res.status(400).json({ error: 'Invalid project id' });
  const project = await projectsCollection.findOne({ _id: projectObjectId, user_id: req.userId });
  if (!project) return res.status(404).json({ error: 'Project not found' });
  const apis = await apisCollection
    .find({ project_id: projectId, user_id: req.userId })
    .sort({ created_at: -1 })
    .toArray();
  res.json(apis);
});

app.post('/api/projects/:projectId/apis', ensureAuth, async (req, res) => {
  const { projectId } = req.params;
  const {
    name,
    method = 'GET',
    endpoint = '',
    headers = {},
    query_params = {},
    body = '',
    body_mode = 'raw',
    response_example = null,
    description = '',
    auth = { type: 'no_auth' }
  } = req.body || {};

  if (!name || !String(name).trim()) {
    return res.status(400).json({ error: 'API name is required' });
  }

  const now = new Date();
  const doc = {
    user_id: req.userId,
    project_id: projectId,
    name: String(name).trim(),
    method: String(method || 'GET').toUpperCase(),
    endpoint: String(endpoint || '').trim(),
    headers: safeJsonParse(headers, {}),
    query_params: safeJsonParse(query_params, {}),
    body: body_mode === 'form-data' ? Object.fromEntries(parseFormDataLines(body)) : (typeof body === 'string' ? body : JSON.stringify(body || '')),
    body_mode: body_mode === 'form-data' ? 'form-data' : 'raw',
    response_example: safeJsonParse(response_example, null),
    last_response_body: null,
    last_response_headers: null,
    last_status: null,
    last_response_time: null,
    last_run_at: null,
    last_curl_command: null,
    auth: safeJsonParse(auth, { type: 'no_auth' }),
    description: String(description || '').trim(),
    created_at: now
  };
  const result = await apisCollection.insertOne(doc);
  res.status(201).json({ ...doc, _id: result.insertedId });
});

app.put('/api/apis/:apiId', ensureAuth, async (req, res) => {
  const { apiId } = req.params;
  const apiObjectId = parseObjectId(apiId);
  if (!apiObjectId) return res.status(400).json({ error: 'Invalid api id' });
  const updates = req.body || {};
  const updateDoc = {
    ...(updates.name ? { name: String(updates.name).trim() } : {}),
    ...(updates.method ? { method: String(updates.method).toUpperCase() } : {}),
    ...(updates.endpoint !== undefined ? { endpoint: String(updates.endpoint || '').trim() } : {}),
    ...(updates.headers !== undefined ? { headers: safeJsonParse(updates.headers, {}) } : {}),
    ...(updates.query_params !== undefined ? { query_params: safeJsonParse(updates.query_params, {}) } : {}),
    ...(updates.body !== undefined
      ? {
        body: updates.body_mode === 'form-data'
          ? Object.fromEntries(parseFormDataLines(updates.body))
          : (typeof updates.body === 'string' ? updates.body : JSON.stringify(updates.body))
      }
      : {}),
    ...(updates.body_mode !== undefined ? { body_mode: updates.body_mode === 'form-data' ? 'form-data' : 'raw' } : {}),
    ...(updates.response_example !== undefined ? { response_example: safeJsonParse(updates.response_example, null) } : {}),
    ...(updates.auth !== undefined ? { auth: safeJsonParse(updates.auth, { type: 'no_auth' }) } : {}),
    ...(updates.description !== undefined ? { description: String(updates.description || '').trim() } : {})
  };

  await apisCollection.updateOne(
    { _id: apiObjectId, user_id: req.userId },
    { $set: updateDoc }
  );

  const api = await apisCollection.findOne({ _id: apiObjectId, user_id: req.userId });
  if (!api) return res.status(404).json({ error: 'API not found' });
  res.json(api);
});

app.delete('/api/apis/:apiId', ensureAuth, async (req, res) => {
  const { apiId } = req.params;
  const apiObjectId = parseObjectId(apiId);
  if (!apiObjectId) return res.status(400).json({ error: 'Invalid api id' });

  const existing = await apisCollection.findOne({ _id: apiObjectId, user_id: req.userId });
  if (!existing) return res.status(404).json({ error: 'API not found' });

  await apisCollection.deleteOne({ _id: apiObjectId, user_id: req.userId });
  await apiResponsesCollection.deleteMany({ api_id: apiId, user_id: req.userId });
  await apiCurlsCollection.deleteMany({ api_id: apiId, user_id: req.userId });
  await runHistoryCollection.deleteMany({ api_id: apiId, user_id: req.userId });

  res.json({ success: true, deleted_api_id: apiId });
});

app.get('/api/apis/:apiId/history', ensureAuth, async (req, res) => {
  const { apiId } = req.params;
  const history = await apiResponsesCollection
    .find({ api_id: apiId, user_id: req.userId })
    .sort({ created_at: -1 })
    .limit(100)
    .toArray();
  res.json(history);
});

app.get('/api/apis/:apiId/curls', ensureAuth, async (req, res) => {
  const { apiId } = req.params;
  const curls = await apiCurlsCollection
    .find({ api_id: apiId, user_id: req.userId })
    .sort({ created_at: -1 })
    .limit(100)
    .toArray();
  res.json(curls);
});

app.get('/api/history', ensureAuth, async (req, res) => {
  const { apiId = '', projectId = '' } = req.query;
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);

  const filter = { user_id: req.userId };
  if (apiId) filter.api_id = String(apiId);
  if (projectId) filter.project_id = String(projectId);

  const rows = await runHistoryCollection
    .find(filter)
    .sort({ created_at: -1 })
    .limit(limit)
    .toArray();

  res.json(rows);
});

app.delete('/api/history/:historyId', ensureAuth, async (req, res) => {
  const { historyId } = req.params;
  const historyObjectId = parseObjectId(historyId);
  if (!historyObjectId) return res.status(400).json({ error: 'Invalid history id' });

  const result = await runHistoryCollection.deleteOne({ _id: historyObjectId, user_id: req.userId });
  if (result.deletedCount === 0) {
    return res.status(404).json({ error: 'History row not found' });
  }

  return res.json({ success: true, deleted_history_id: historyId });
});

app.get('/api/projects/:projectId/export', ensureAuth, async (req, res) => {
  const { projectId } = req.params;
  const format = String(req.query.format || 'excel').toLowerCase();
  const projectObjectId = parseObjectId(projectId);
  if (!projectObjectId) return res.status(400).json({ error: 'Invalid project id' });
  const project = await projectsCollection.findOne({ _id: projectObjectId, user_id: req.userId });
  if (!project) return res.status(404).json({ error: 'Project not found' });

  const apis = await apisCollection.find({ project_id: projectId, user_id: req.userId }).toArray();

  if (format === 'curl') {
    const lines = apis.map((api) => buildCurlCommandByMode({
      method: api.method || 'GET',
      url: `${project.base_url || ''}${api.endpoint || ''}`,
      headers: api.headers || {},
      body: api.body || '',
      bodyMode: api.body_mode || 'raw'
    }));
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${project.name.replace(/\s+/g, '_')}_collection.sh"`);
    return res.send(lines.join('\n\n'));
  }

  if (format === 'pdf') {
    const lines = [
      `Project: ${project.name}`,
      `Base URL: ${project.base_url || '-'}`,
      '',
      'APIs:'
    ];

    for (const api of apis) {
      const latestResponse = await apiResponsesCollection.findOne(
        { api_id: String(api._id), user_id: req.userId },
        { sort: { created_at: -1 } }
      );
      lines.push(`- ${api.method || 'GET'} ${api.endpoint || ''} (${api.name || 'Unnamed API'})`);
      lines.push(`  Request Body: ${typeof api.body === 'string' ? api.body : JSON.stringify(api.body || {})}`);
      lines.push(`  Response Body: ${JSON.stringify(latestResponse?.response_body || api.last_response_body || {}, null, 2)}`);
      lines.push('');
    }

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${project.name.replace(/\s+/g, '_')}_report.txt"`);
    return res.send(lines.join('\n'));
  }

  const headers = ['API', 'Method', 'URL', 'Request', 'Response'];
  const rows = [headers.join(',')];

  for (const api of apis) {
    const latestResponse = await apiResponsesCollection.findOne(
      { api_id: String(api._id), user_id: req.userId },
      { sort: { created_at: -1 } }
    );
    const requestSummary = JSON.stringify({
      headers: api.headers || {},
      query_params: api.query_params || {},
      body: api.body || ''
    }).replace(/"/g, '""');
    const responseSummary = JSON.stringify(latestResponse?.response_body || {}).replace(/"/g, '""');
    rows.push(`"${api.name || ''}","${api.method || ''}","${(project.base_url || '') + (api.endpoint || '')}","${requestSummary}","${responseSummary}"`);
  }

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${project.name.replace(/\s+/g, '_')}_export.csv"`);
  return res.send(rows.join('\n'));
});

app.post('/api/apis/:apiId/run', ensureAuth, async (req, res) => {
  const { apiId } = req.params;
  const apiObjectId = parseObjectId(apiId);
  if (!apiObjectId) return res.status(400).json({ error: 'Invalid api id' });
  const api = await apisCollection.findOne({ _id: apiObjectId, user_id: req.userId });
  if (!api) return res.status(404).json({ error: 'API not found' });

  const projectObjectId = parseObjectId(api.project_id);
  if (!projectObjectId) return res.status(400).json({ error: 'Invalid linked project id' });
  const project = await projectsCollection.findOne({ _id: projectObjectId, user_id: req.userId });
  if (!project) return res.status(400).json({ error: 'Project not found for API' });

  const overrides = req.body || {};
  const method = String(overrides.method || api.method || 'GET').toUpperCase();
  const endpoint = String(overrides.endpoint || api.endpoint || '').trim();
  const fullUrl = /^https?:\/\//i.test(endpoint) ? endpoint : `${project.base_url || ''}${endpoint}`;
  const headers = safeJsonParse(overrides.headers ?? api.headers, {});
  const body = overrides.body !== undefined ? overrides.body : (api.body || '');
  const bodyMode = overrides.body_mode || api.body_mode || 'raw';
  const formFiles = Array.isArray(overrides.form_files) ? overrides.form_files : [];

  const requestPayload = { method, url: fullUrl, headers, body, body_mode: bodyMode, form_files: formFiles };
  const upstream = await executeUpstreamRequest(requestPayload);
  if (upstream.error) {
    return res.status(upstream.statusCode).json({ error: upstream.error, details: upstream.details || null });
  }

  const now = new Date();
  const responsePayload = upstream.payload;
  const curlCommand = buildCurlCommandByMode({ method, url: fullUrl, headers, body, bodyMode });

  await saveApiResponse({
    user_id: req.userId,
    api_id: apiId,
    method,
    url: fullUrl,
    endpoint,
    api_name: api.name || '',
    project_id: api.project_id,
    status: responsePayload.status,
    response_body: responsePayload.body,
    response_headers: responsePayload.headers,
    request_headers: headers,
    request_body: bodyMode === 'form-data'
      ? [formDataObjectToLines(body), formFilesToLines(formFiles)].filter(Boolean).join('\n')
      : body,
    response_time: responsePayload.durationMs,
    created_at: now
  });

  await saveApiCurl({
    user_id: req.userId,
    api_id: apiId,
    method,
    url: fullUrl,
    request_body: bodyMode === 'form-data'
      ? [formDataObjectToLines(body), formFilesToLines(formFiles)].filter(Boolean).join('\n')
      : body,
    response_body: responsePayload.body,
    response_status: responsePayload.status,
    curl_command: curlCommand,
    created_at: now
  });

  await apisCollection.updateOne(
    { _id: apiObjectId, user_id: req.userId },
    {
      $set: {
        last_response_body: responsePayload.body,
        last_response_headers: responsePayload.headers,
        last_status: responsePayload.status,
        last_response_time: responsePayload.durationMs,
        last_run_at: now,
        last_curl_command: curlCommand,
        body_mode: bodyMode === 'form-data' ? 'form-data' : 'raw',
        response_example: responsePayload.body
      }
    }
  );

  await saveRunHistory({
    user_id: req.userId,
    source: 'saved_api',
    api_id: apiId,
    project_id: api.project_id,
    api_name: api.name || '',
    method,
    endpoint,
    url: fullUrl,
    status: responsePayload.status,
    status_text: responsePayload.statusText,
    response_time: responsePayload.durationMs,
    request_headers: headers,
    request_body: bodyMode === 'form-data'
      ? [formDataObjectToLines(body), formFilesToLines(formFiles)].filter(Boolean).join('\n')
      : body,
    curl_command: curlCommand,
    response_headers: responsePayload.headers,
    response_body: responsePayload.body,
    created_at: now
  });

  return res.json(responsePayload);
});

app.post('/api/proxy-request', async (req, res) => {
  const result = await executeUpstreamRequest(req.body || {});
  if (result.error) {
    return res.status(result.statusCode).json({
      error: result.error,
      details: result.details || null
    });
  }

  try {
    const userId = await resolveCurrentUser(req);
    if (userId) {
      const requestMethod = String(req.body?.method || 'GET').toUpperCase();
      const requestUrl = String(req.body?.url || '');
      const requestHeaders = safeJsonParse(req.body?.headers, {});
      const requestBody = req.body?.body ?? '';
      const bodyMode = req.body?.body_mode === 'form-data' ? 'form-data' : 'raw';
      const formFiles = Array.isArray(req.body?.form_files) ? req.body.form_files : [];
      const payload = result.payload;
      const now = new Date();
      const curlCommand = buildCurlCommandByMode({
        method: requestMethod,
        url: requestUrl,
        headers: requestHeaders,
        body: requestBody,
        bodyMode
      });

      await saveApiResponse({
        user_id: userId,
        api_id: null,
        method: requestMethod,
        url: requestUrl,
        endpoint: requestUrl,
        api_name: req.body?.name || 'Adhoc Request',
        project_id: null,
        status: payload.status,
        response_body: payload.body,
        response_headers: payload.headers,
        request_headers: requestHeaders,
        request_body: bodyMode === 'form-data'
          ? [formDataObjectToLines(requestBody), formFilesToLines(formFiles)].filter(Boolean).join('\n')
          : requestBody,
        response_time: payload.durationMs,
        created_at: now
      });

      await saveApiCurl({
        user_id: userId,
        api_id: null,
        method: requestMethod,
        url: requestUrl,
        request_body: bodyMode === 'form-data'
          ? [formDataObjectToLines(requestBody), formFilesToLines(formFiles)].filter(Boolean).join('\n')
          : requestBody,
        response_body: payload.body,
        response_status: payload.status,
        curl_command: curlCommand,
        created_at: now
      });

      await saveRunHistory({
        user_id: userId,
        source: 'adhoc',
        api_id: null,
        project_id: null,
        api_name: req.body?.name || 'Adhoc Request',
        method: requestMethod,
        endpoint: requestUrl,
        url: requestUrl,
        status: payload.status,
        status_text: payload.statusText,
        response_time: payload.durationMs,
        request_headers: requestHeaders,
        request_body: bodyMode === 'form-data'
          ? [formDataObjectToLines(requestBody), formFilesToLines(formFiles)].filter(Boolean).join('\n')
          : requestBody,
        curl_command: curlCommand,
        response_headers: payload.headers,
        response_body: payload.body,
        created_at: now
      });
    }
  } catch (error) {
    // Ignore history persistence errors for adhoc mode.
  }

  return res.json(result.payload);
});

// Existing APIs
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), user: req.user || null });
});

app.post('/api/track', (req, res) => {
  console.log('API Track:', req.body);
  res.json({ message: 'API call tracked', data: req.body, user: req.user || null });
});

// Serve Frontend - Prod (dist) or fallback HTML
app.use(express.static(path.join(__dirname, 'frontend/dist')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend/dist/index.html'));
});

// For dev: Proxy to Vite? Optional - use vite proxy config instead.

// 404 fallback
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

(async () => {
  try {
    await initDatabase();
    app.listen(port, () => {
      console.log(`API Tracker running at http://localhost:${port}`);
      console.log(hasGoogleOAuth ? 'Google Auth: Configured' : 'Google Auth: Not configured');
      console.log('Frontend dev: cd frontend && npm run dev');
    });
  } catch (error) {
    console.error('Database initialization failed:', error.message);
    process.exit(1);
  }
})();
