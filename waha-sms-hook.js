const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} = require('@simplewebauthn/server');

const app = express();
const port = Number(process.env.PORT || 3001);
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const wahaUrl = (process.env.WAHA_URL || '').replace(/\/$/, '');
const wahaSession = process.env.WAHA_SESSION || 'default';
const wahaApiKey = process.env.WAHA_API_KEY || '';
const otpTtlMs = 5 * 60 * 1000;
const otpStore = new Map();
const webauthnRpId = process.env.WEBAUTHN_RP_ID || 'partner.ronat.asia';
const webauthnOrigin = process.env.WEBAUTHN_ORIGIN || 'https://partner.ronat.asia';
const webauthnChallengeTtlMs = 5 * 60 * 1000;
const webauthnChallenges = new Map();

app.use(express.json({ limit: '1mb' }));

function normalizePhone(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  if (digits.startsWith('8') && digits.length === 11) return `7${digits.slice(1)}`;
  if (digits.length === 10) return `7${digits}`;
  return digits;
}

async function findAuthUser(phone) {
  if (!supabaseUrl || !supabaseServiceRoleKey) {
    throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required');
  }

  const response = await axios.post(`${supabaseUrl}/rest/v1/rpc/check_auth_phone`, {
    phone_input: phone
  }, {
    headers: {
      apikey: supabaseServiceRoleKey,
      Authorization: `Bearer ${supabaseServiceRoleKey}`,
      'Content-Type': 'application/json'
    },
    timeout: 10000
  });

  return response.data || null;
}

function serviceHeaders() {
  return {
    apikey: supabaseServiceRoleKey,
    Authorization: `Bearer ${supabaseServiceRoleKey}`,
    'Content-Type': 'application/json'
  };
}

function createSessionToken(userId) {
  const payload = Buffer.from(JSON.stringify({
    uid: userId,
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', supabaseServiceRoleKey).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function getSessionUserId(req) {
  const [scheme, token] = String(req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) return null;

  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;

  const expectedSignature = crypto.createHmac('sha256', supabaseServiceRoleKey).update(payload).digest();
  let providedSignature;
  try {
    providedSignature = Buffer.from(signature, 'base64url');
  } catch {
    return null;
  }
  if (providedSignature.length !== expectedSignature.length || !crypto.timingSafeEqual(providedSignature, expectedSignature)) return null;

  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return typeof session.uid === 'string' && session.exp > Date.now() ? session.uid : null;
  } catch {
    return null;
  }
}

async function findProfile(userId) {
  const columns = [
    'email', 'role', 'familiya', 'imya', 'otchestvo', 'IIN', 'telefon', 'created_at',
    'numberUdostLichnosti', 'kemVydan', 'kogdaVudan', 'adrespropiski',
    'avatar', 'dateRozhdeniya', 'city', 'city_id', 'compani_name', 'compani_id'
  ].join(',');
  const response = await axios.get(`${supabaseUrl}/rest/v1/profiles`, {
    params: { id: `eq.${userId}`, select: `id,${columns}`, limit: 1 },
    headers: serviceHeaders(),
    timeout: 10000
  });
  return response.data?.[0] || null;
}

async function findWebAuthnCredentials(userId) {
  const response = await axios.get(`${supabaseUrl}/rest/v1/webauthn_credentials`, {
    params: {
      user_id: `eq.${userId}`,
      select: 'credential_id,public_key,counter,transports'
    },
    headers: serviceHeaders(),
    timeout: 10000
  });
  return response.data || [];
}

function saveWebAuthnChallenge(challenge, type, userId = null) {
  const now = Date.now();
  for (const [key, value] of webauthnChallenges) {
    if (value.expiresAt <= now) webauthnChallenges.delete(key);
  }
  webauthnChallenges.set(challenge, { type, userId, expiresAt: now + webauthnChallengeTtlMs });
}

function consumeWebAuthnChallenge(challenge, type, userId = null) {
  const saved = webauthnChallenges.get(challenge);
  webauthnChallenges.delete(challenge);
  return Boolean(saved && saved.type === type && saved.userId === userId && saved.expiresAt > Date.now());
}

function webauthnErrorResponse(res, error, label) {
  console.error(`[Passkey] Ошибка ${label}:`, {
    status: error.response?.status || null,
    details: error.response?.data || error.message
  });
  if (error.response?.status === 404) {
    return res.status(503).json({ error: 'Хранилище ключей входа не настроено. Выполните миграцию passkeys.sql в Supabase.' });
  }
  return res.status(502).json({ error: `Не удалось выполнить ${label}. Проверьте настройки WebAuthn и Supabase.` });
}

async function sendOtp(phone, otp) {
  if (!wahaUrl) {
    const error = new Error('WAHA_URL is not configured');
    error.code = 'WAHA_NOT_CONFIGURED';
    throw error;
  }

  const headers = { 'Content-Type': 'application/json' };
  if (wahaApiKey) headers['X-Api-Key'] = wahaApiKey;
  try {
    await axios.post(`${wahaUrl}/api/sendText`, {
      chatId: `${phone}@c.us`,
      text: `Ваш код входа в R-invest: ${otp}. Код действителен 5 минут.`,
      session: wahaSession
    }, { headers, timeout: 10000 });
  } catch (error) {
    error.code = 'WAHA_SEND_FAILED';
    throw error;
  }
}

app.post('/api/auth/check-phone', async (req, res) => {
  try {
    if (!supabaseUrl || !supabaseServiceRoleKey || supabaseServiceRoleKey === 'replace-with-service-role-key') {
      return res.status(500).json({ error: 'На сервере не настроен SUPABASE_SERVICE_ROLE_KEY' });
    }

    const phone = normalizePhone(req.body?.phone);
    if (phone.length !== 11 || !phone.startsWith('7')) {
      return res.status(400).json({ error: 'Введите корректный номер телефона' });
    }

    const user = await findAuthUser(phone);
    if (!user) return res.status(403).json({ error: 'Доступ запрещен. Номер не зарегистрирован в Authentication' });

    const otp = String(crypto.randomInt(100000, 1000000));
    await sendOtp(phone, otp);
    otpStore.set(phone, { uid: user.id, otp, expiresAt: Date.now() + otpTtlMs, attempts: 0 });

    return res.json({ ok: true });
  } catch (error) {
    const upstreamStatus = error.response?.status;
    const upstreamDetails = error.response?.data;
    const networkCode = error.code || 'UNKNOWN';
    console.error('[Auth] Ошибка проверки телефона:', {
      status: upstreamStatus || null,
      code: networkCode,
      details: upstreamDetails || error.message
    });

    if (upstreamStatus === 401 || upstreamStatus === 403) {
      return res.status(502).json({ error: 'Supabase отклонил service-role ключ. Проверьте SUPABASE_SERVICE_ROLE_KEY' });
    }
    if (error.code === 'WAHA_NOT_CONFIGURED' || error.code === 'WAHA_SEND_FAILED') {
      return res.status(502).json({ error: 'Не удалось отправить код в WhatsApp. Проверьте WAHA и его сессию' });
    }
    if (upstreamStatus) {
      const details = typeof upstreamDetails === 'string'
        ? upstreamDetails.slice(0, 300)
        : upstreamDetails?.msg || upstreamDetails?.message || upstreamDetails?.error;
      return res.status(502).json({
        error: `Supabase RPC проверки телефона вернул HTTP ${upstreamStatus}`,
        details: details || 'Supabase не передал описание ошибки'
      });
    }
    return res.status(502).json({ error: `Не удалось подключиться к Supabase RPC (${networkCode})` });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  const phone = normalizePhone(req.body?.phone);
  const otp = String(req.body?.otp || '').replace(/\D/g, '');
  const pending = otpStore.get(phone);

  if (!pending || pending.expiresAt < Date.now()) {
    otpStore.delete(phone);
    return res.status(400).json({ error: 'Код истёк. Запросите новый код' });
  }

  pending.attempts += 1;
  if (pending.attempts > 5) {
    otpStore.delete(phone);
    return res.status(429).json({ error: 'Превышено число попыток. Запросите новый код' });
  }
  if (otp !== pending.otp) return res.status(401).json({ error: 'Неверный код подтверждения' });

  const profile = await findProfile(pending.uid);
  if (!profile) return res.status(404).json({ error: 'Профиль пользователя не найден' });

  otpStore.delete(phone);
  return res.json({ ok: true, uid: pending.uid, profile, sessionToken: createSessionToken(pending.uid) });
});

app.get('/api/auth/passkey/status', async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) return res.status(401).json({ error: 'Сессия истекла. Войдите по номеру телефона' });
  try {
    const credentials = await findWebAuthnCredentials(userId);
    return res.json({ hasPasskey: credentials.length > 0 });
  } catch (error) {
    return webauthnErrorResponse(res, error, 'проверку ключа входа');
  }
});

app.post('/api/auth/passkey/register/options', async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) return res.status(401).json({ error: 'Сессия истекла. Войдите по номеру телефона' });
  try {
    const profile = await findProfile(userId);
    if (!profile) return res.status(404).json({ error: 'Профиль пользователя не найден' });
    const credentials = await findWebAuthnCredentials(userId);
    const options = await generateRegistrationOptions({
      rpName: 'R-invest',
      rpID: webauthnRpId,
      userID: Buffer.from(userId, 'utf8'),
      userName: profile.telefon || profile.email || userId,
      userDisplayName: [profile.familiya, profile.imya].filter(Boolean).join(' ') || 'Партнёр R-invest',
      attestationType: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        userVerification: 'required'
      },
      excludeCredentials: credentials.map(credential => ({
        id: credential.credential_id,
        transports: credential.transports
      }))
    });
    saveWebAuthnChallenge(options.challenge, 'registration', userId);
    return res.json(options);
  } catch (error) {
    return webauthnErrorResponse(res, error, 'подготовку passkey');
  }
});

app.post('/api/auth/passkey/register/verify', async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) return res.status(401).json({ error: 'Сессия истекла. Войдите по номеру телефона' });
  const { challenge, credential } = req.body || {};
  if (typeof challenge !== 'string' || !credential || typeof credential !== 'object') {
    return res.status(400).json({ error: 'Не переданы данные ключа входа' });
  }
  if (!consumeWebAuthnChallenge(challenge, 'registration', userId)) {
    return res.status(400).json({ error: 'Запрос регистрации истёк. Повторите настройку ключа' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: webauthnOrigin,
      expectedRPID: webauthnRpId,
      requireUserVerification: true
    });
    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Не удалось подтвердить ключ входа на устройстве' });
    }
    const registration = verification.registrationInfo;
    const credentialId = Buffer.from(registration.credentialID).toString('base64url');
    const existing = await axios.get(`${supabaseUrl}/rest/v1/webauthn_credentials`, {
      params: { credential_id: `eq.${credentialId}`, select: 'user_id', limit: 1 },
      headers: serviceHeaders(),
      timeout: 10000
    });
    if (existing.data?.length && existing.data[0].user_id !== userId) {
      return res.status(409).json({ error: 'Этот ключ уже зарегистрирован для другого аккаунта' });
    }
    if (existing.data?.length) {
      return res.json({ verified: true });
    }
    await axios.post(`${supabaseUrl}/rest/v1/webauthn_credentials`, {
      credential_id: credentialId,
      user_id: userId,
      public_key: Buffer.from(registration.credentialPublicKey).toString('base64url'),
      counter: registration.counter,
      transports: credential.response.transports || []
    }, {
      headers: { ...serviceHeaders(), Prefer: 'return=minimal' },
      timeout: 10000
    });
    return res.json({ verified: true });
  } catch (error) {
    return webauthnErrorResponse(res, error, 'регистрацию ключа входа');
  }
});

app.post('/api/auth/passkey/login/options', async (req, res) => {
  try {
    const options = await generateAuthenticationOptions({
      rpID: webauthnRpId,
      userVerification: 'required',
      allowCredentials: []
    });
    saveWebAuthnChallenge(options.challenge, 'authentication');
    return res.json(options);
  } catch (error) {
    return webauthnErrorResponse(res, error, 'подготовку входа по passkey');
  }
});

app.post('/api/auth/passkey/login/verify', async (req, res) => {
  const { challenge, credential } = req.body || {};
  if (typeof challenge !== 'string' || !credential || typeof credential.id !== 'string') {
    return res.status(400).json({ error: 'Не переданы данные для входа по ключу' });
  }
  if (!consumeWebAuthnChallenge(challenge, 'authentication')) {
    return res.status(400).json({ error: 'Запрос входа истёк. Попробуйте ещё раз' });
  }

  try {
    const credentialResponse = await axios.get(`${supabaseUrl}/rest/v1/webauthn_credentials`, {
      params: {
        credential_id: `eq.${credential.id}`,
        select: 'credential_id,user_id,public_key,counter,transports',
        limit: 1
      },
      headers: serviceHeaders(),
      timeout: 10000
    });
    const stored = credentialResponse.data?.[0];
    if (!stored) return res.status(404).json({ error: 'Ключ не найден. Войдите по номеру телефона и настройте его заново' });

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: webauthnOrigin,
      expectedRPID: webauthnRpId,
      authenticator: {
        credentialID: Buffer.from(stored.credential_id, 'base64url'),
        credentialPublicKey: Buffer.from(stored.public_key, 'base64url'),
        counter: Number(stored.counter),
        transports: stored.transports
      },
      requireUserVerification: true
    });
    if (!verification.verified) return res.status(401).json({ error: 'Не удалось подтвердить ключ входа' });

    const userHandle = credential.response?.userHandle;
    if (!userHandle || Buffer.from(userHandle, 'base64url').toString('utf8') !== stored.user_id) {
      return res.status(401).json({ error: 'Ключ не подтвердил владельца аккаунта' });
    }
    const newCounter = verification.authenticationInfo.newCounter;
    await axios.patch(`${supabaseUrl}/rest/v1/webauthn_credentials`, {
      counter: newCounter
    }, {
      params: { credential_id: `eq.${stored.credential_id}` },
      headers: { ...serviceHeaders(), Prefer: 'return=minimal' },
      timeout: 10000
    });
    const profile = await findProfile(stored.user_id);
    if (!profile) return res.status(404).json({ error: 'Профиль пользователя не найден' });
    return res.json({
      ok: true,
      uid: stored.user_id,
      profile,
      sessionToken: createSessionToken(stored.user_id)
    });
  } catch (error) {
    if (error.name === 'WebAuthnError') {
      return res.status(401).json({ error: 'Ключ не подошёл. Попробуйте ещё раз или войдите по телефону' });
    }
    return webauthnErrorResponse(res, error, 'вход по passkey');
  }
});

app.get('/api/profile', async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) return res.status(401).json({ error: 'Сессия истекла. Войдите в аккаунт повторно' });
  try {
    const profile = await findProfile(userId);
    if (!profile) return res.status(404).json({ error: 'Профиль пользователя не найден' });
    return res.json({ profile });
  } catch (error) {
    console.error('[Profile] Ошибка загрузки профиля:', {
      status: error.response?.status || null,
      details: error.response?.data || error.message
    });
    return res.status(502).json({ error: 'Не удалось загрузить данные профиля' });
  }
});

app.put('/api/profile', async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) return res.status(401).json({ error: 'Сессия истекла. Войдите в аккаунт повторно' });
  const profileId = req.body?.id;
  if (typeof profileId !== 'string' || !profileId.trim()) {
    return res.status(400).json({ error: 'Не указан ID профиля' });
  }
  if (profileId !== userId) {
    return res.status(403).json({ error: 'ID профиля не совпадает с текущей сессией' });
  }

  const allowedFields = ['familiya', 'imya', 'otchestvo', 'IIN', 'dateRozhdeniya', 'avatar'];
  const updates = {};
  for (const field of allowedFields) {
    if (!Object.prototype.hasOwnProperty.call(req.body || {}, field)) continue;
    if (field === 'dateRozhdeniya' && req.body[field] === null) {
      updates[field] = null;
      continue;
    }
    if (typeof req.body[field] !== 'string') {
      return res.status(400).json({ error: `Поле ${field} должно быть строкой` });
    }
    updates[field] = req.body[field].trim();
  }

  if (!Object.keys(updates).length) {
    return res.status(400).json({ error: 'Не переданы данные для сохранения' });
  }
  for (const field of ['familiya', 'imya', 'otchestvo']) {
    if (updates[field] !== undefined && updates[field].length > 100) {
      return res.status(400).json({ error: `Поле ${field} не должно превышать 100 символов` });
    }
  }
  if (updates.IIN && !/^\d{12}$/.test(updates.IIN)) {
    return res.status(400).json({ error: 'ИИН должен содержать 12 цифр' });
  }
  if (updates.dateRozhdeniya) {
    const parsedDate = new Date(`${updates.dateRozhdeniya}T00:00:00.000Z`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(updates.dateRozhdeniya) ||
      !Number.isFinite(parsedDate.getTime()) ||
      parsedDate.toISOString().slice(0, 10) !== updates.dateRozhdeniya) {
      return res.status(400).json({ error: 'Укажите корректную дату рождения в формате ГГГГ-ММ-ДД' });
    }
  }
  if (updates.avatar && (
    updates.avatar.length > 450000 ||
    !/^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(updates.avatar)
  )) {
    return res.status(400).json({ error: 'Аватар должен быть изображением JPEG, PNG или WebP размером до 450 КБ' });
  }

  try {
    const updateResponse = await axios.patch(`${supabaseUrl}/rest/v1/profiles`, updates, {
      params: { id: `eq.${profileId}`, select: 'id' },
      headers: { ...serviceHeaders(), Prefer: 'return=representation' },
      timeout: 10000
    });
    if (!Array.isArray(updateResponse.data) || updateResponse.data.length !== 1) {
      return res.status(404).json({ error: 'Профиль с указанным ID не найден' });
    }
    const profile = await findProfile(profileId);
    if (!profile) return res.status(404).json({ error: 'Профиль пользователя не найден после сохранения' });
    return res.json({ profile });
  } catch (error) {
    console.error('[Profile] Ошибка сохранения профиля:', {
      status: error.response?.status || null,
      details: error.response?.data || error.message
    });
    return res.status(502).json({ error: 'Не удалось сохранить данные профиля' });
  }
});

app.get('/api/partner/cars', async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) return res.status(401).json({ error: 'Сессия истекла. Войдите в аккаунт повторно' });
  if (req.query.hozyain_id !== userId) {
    return res.status(403).json({ error: 'ID партнёра не совпадает с текущей сессией' });
  }

  try {
    const response = await axios.get(`${supabaseUrl}/rest/v1/cars`, {
      params: {
        hozyain_id: `eq.${userId}`,
        select: 'id,marka,model,gos_nomer,photo_avto',
        order: 'id.asc'
      },
      headers: { ...serviceHeaders(), Prefer: 'count=exact' },
      timeout: 10000
    });
    const total = Number(response.headers['content-range']?.split('/')[1]);
    const cars = response.data || [];
    if (cars.length) {
      const profile = await findProfile(userId);
      if (!profile) return res.status(404).json({ error: 'Профиль пользователя не найден' });

      const filterValue = value => value == null ? 'is.null' : `eq.${value}`;
      const contractsResponse = await axios.get(`${supabaseUrl}/rest/v1/contracts`, {
        params: {
          car_hozyain_id: `eq.${userId}`,
          compani_id: filterValue(profile.compani_id),
          city_id: filterValue(profile.city_id),
          car_id: `in.(${cars.map(car => car.id).join(',')})`,
          select: 'car_id,date_nachala_arendy,date_okonchaniya_arendy,status_dogovora',
          order: 'status_dogovora.desc,date_nachala_arendy.desc'
        },
        headers: { ...serviceHeaders(), Prefer: 'count=exact' },
        timeout: 10000
      });

      const contractByCarId = new Map();
      (contractsResponse.data || []).forEach(contract => {
        const carId = String(contract.car_id);
        if (!contractByCarId.has(carId)) contractByCarId.set(carId, contract);
      });
      cars.forEach(car => {
        car.subleaseContract = contractByCarId.get(String(car.id)) || null;
      });
    }

    return res.json({ cars, count: Number.isFinite(total) ? total : cars.length });
  } catch (error) {
    console.error('[Cars] Ошибка загрузки автомобилей:', {
      status: error.response?.status || null,
      details: error.response?.data || error.message
    });
    return res.status(502).json({ error: 'Не удалось загрузить автомобили партнёра' });
  }
});

app.get('/api/partner/sublease-cars', async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) return res.status(401).json({ error: 'Сессия истекла. Войдите в аккаунт повторно' });
  const countOnly = req.query.count_only === 'true';

  try {
    const profile = await findProfile(userId);
    if (!profile) return res.status(404).json({ error: 'Профиль пользователя не найден' });

    const filterValue = value => value == null ? 'is.null' : `eq.${value}`;
    const response = await axios.get(`${supabaseUrl}/rest/v1/cars`, {
      params: {
        hozyain_id: `eq.${userId}`,
        kompaniya_id: filterValue(profile.compani_id),
        cityID: filterValue(profile.city_id),
        arfive: 'eq.false',
        select: countOnly ? 'date_start_dogovor,date_end_dogovor' : 'id,photo_avto,marka,model,gos_nomer,date_start_dogovor,date_end_dogovor,dogovor_subarendy_url',
        order: 'id.asc'
      },
      headers: { ...serviceHeaders(), Prefer: 'count=exact' },
      timeout: 10000
    });

    const cars = response.data || [];
    const total = Number(response.headers['content-range']?.split('/')[1]);
    const now = Date.now();
    const activeCount = cars.filter(car => {
      const start = Date.parse(car.date_start_dogovor);
      const end = Date.parse(car.date_end_dogovor);
      return Number.isFinite(start) && Number.isFinite(end) && start <= now && end >= now;
    }).length;
    if (countOnly) return res.json({ activeCount });
    return res.json({ cars, count: Number.isFinite(total) ? total : cars.length, activeCount });
  } catch (error) {
    console.error('[Sublease] Ошибка загрузки договоров субаренды:', {
      status: error.response?.status || null,
      details: error.response?.data || error.message
    });
    return res.status(502).json({ error: 'Не удалось загрузить договора субаренды' });
  }
});

app.get('/api/partner/contracts', async (req, res) => {
  const userId = getSessionUserId(req);
  if (!userId) return res.status(401).json({ error: 'Сессия истекла. Войдите в аккаунт повторно' });

  const offset = Number(req.query.offset ?? 0);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1000000) {
    return res.status(400).json({ error: 'Некорректный номер страницы аренд' });
  }
  const status = String(req.query.status || 'all');
  if (!['all', 'active', 'completed'].includes(status)) {
    return res.status(400).json({ error: 'Некорректный фильтр статуса договора' });
  }
  const modelSearch = String(req.query.model || '').trim();
  if (modelSearch.length > 100) {
    return res.status(400).json({ error: 'Слишком длинный поисковый запрос модели автомобиля' });
  }

  try {
    const profile = await findProfile(userId);
    if (!profile) return res.status(404).json({ error: 'Профиль пользователя не найден' });

    const filterValue = value => value == null ? 'is.null' : `eq.${value}`;
    const filters = {
      car_hozyain_id: `eq.${userId}`,
      compani_id: filterValue(profile.compani_id),
      city_id: filterValue(profile.city_id),
      select: 'id,marka_avto,model_avto,gos_nomer,date_nachala_arendy,date_okonchaniya_arendy,vyezd_cena,stoimost_arendy_bez_depozita,status_dogovora',
      order: 'date_nachala_arendy.desc,id.desc'
    };
    if (status !== 'all') filters.status_dogovora = `eq.${status === 'active'}`;
    if (modelSearch) filters.model_avto = `ilike.*${modelSearch}*`;
    const response = await axios.get(`${supabaseUrl}/rest/v1/contracts`, {
      params: filters,
      headers: {
        ...serviceHeaders(),
        Prefer: 'count=exact',
        'Range-Unit': 'items',
        Range: `${offset}-${offset + 2}`
      },
      timeout: 10000
    });

    const total = Number(response.headers['content-range']?.split('/')[1]);
    if (!Number.isFinite(total)) throw new Error('Supabase did not return the exact contract count');

    return res.json({
      contracts: response.data || [],
      count: total
    });
  } catch (error) {
    console.error('[Contracts] Ошибка загрузки аренд:', {
      status: error.response?.status || null,
      details: error.response?.data || error.message
    });
    return res.status(502).json({ error: 'Не удалось загрузить аренды партнёра' });
  }
});

app.listen(port, '0.0.0.0', () => {
  console.info(`Phone authorization service listening on port ${port}`);
});
