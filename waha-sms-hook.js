const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const port = Number(process.env.PORT || 3001);
const wahaUrl = process.env.WAHA_URL || 'http://localhost:3000';
const wahaApiKey = process.env.WAHA_API_KEY || '';
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const authSecret = process.env.AUTH_SECRET || supabaseServiceRoleKey;
const otpTtlMs = 5 * 60 * 1000;
const resendDelayMs = 60 * 1000;
const maxAttempts = 5;
const otpStore = new Map();

app.use(express.json({ limit: '1mb' }));

function normalizePhone(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  if (digits.startsWith('8') && digits.length === 11) return `7${digits.slice(1)}`;
  if (digits.length === 10) return `7${digits}`;
  return digits;
}

function getPhoneVariants(phone) {
  const normalized = normalizePhone(phone);
  if (normalized.length !== 11 || !normalized.startsWith('7')) return [];

  const local = normalized.slice(1);
  return [
    `+${normalized}`,
    normalized,
    `8${local}`,
    local,
    `+7 (${local.slice(0, 3)}) ${local.slice(3, 6)}-${local.slice(6, 8)}-${local.slice(8, 10)}`,
    `8 (${local.slice(0, 3)}) ${local.slice(3, 6)}-${local.slice(6, 8)}-${local.slice(8, 10)}`
  ];
}

async function findProfile(phone) {
  if (!supabaseUrl || !supabaseServiceRoleKey) {
    throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required');
  }

  const variants = getPhoneVariants(phone);
  if (!variants.length) return null;

  const response = await axios.get(`${supabaseUrl}/rest/v1/profiles`, {
    params: {
      select: 'id,email,role,familiya,imya,otchestvo,IIN,telefon,city,city_id',
      telefon: `in.(${variants.join(',')})`,
      limit: 2
    },
    headers: {
      apikey: supabaseServiceRoleKey,
      Authorization: `Bearer ${supabaseServiceRoleKey}`
    },
    timeout: 10000
  });

  if (response.data.length > 1) {
    throw new Error('More than one profile matches this phone number');
  }
  return response.data[0] || null;
}

function hashOtp(phone, code) {
  return crypto.createHmac('sha256', authSecret).update(`${phone}:${code}`).digest('hex');
}

function createSessionToken(profile) {
  const payload = Buffer.from(JSON.stringify({
    sub: profile.id,
    phone: profile.telefon,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', authSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

async function sendWhatsAppCode(phone, code) {
  await axios.post(
    `${wahaUrl}/api/sendText`,
    {
      chatId: `${phone}@c.us`,
      text: `Ваш код авторизации в R-CORE: ${code}`
    },
    {
      headers: {
        'Content-Type': 'application/json',
        ...(wahaApiKey ? { 'X-Api-Key': wahaApiKey } : {})
      },
      timeout: 10000
    }
  );
}

app.post('/api/auth/request-code', async (req, res) => {
  try {
    if (!authSecret) return res.status(500).json({ error: 'AUTH_SECRET is not configured' });

    const phone = normalizePhone(req.body?.phone);
    if (!getPhoneVariants(phone).length) {
      return res.status(400).json({ error: 'Введите корректный номер телефона' });
    }

    const existing = otpStore.get(phone);
    if (existing && Date.now() - existing.createdAt < resendDelayMs) {
      return res.status(429).json({ error: 'Повторно запросить код можно через минуту' });
    }

    const profile = await findProfile(phone);
    if (!profile) return res.status(403).json({ error: 'Доступ запрещен. Номер не зарегистрирован в системе' });

    const code = String(crypto.randomInt(100000, 1000000));
    await sendWhatsAppCode(phone, code);
    otpStore.set(phone, {
      profile,
      codeHash: hashOtp(phone, code),
      createdAt: Date.now(),
      expiresAt: Date.now() + otpTtlMs,
      attempts: 0
    });

    console.info(`[Auth] OTP отправлен через WAHA: ${phone}`);
    return res.json({ ok: true, phone: `+${phone}`, expiresIn: otpTtlMs / 1000 });
  } catch (error) {
    console.error('[Auth] Ошибка запроса OTP:', error.response?.data || error.message);
    return res.status(502).json({ error: 'Не удалось отправить код в WhatsApp' });
  }
});

app.post('/api/auth/verify-code', (req, res) => {
  try {
    if (!authSecret) return res.status(500).json({ error: 'AUTH_SECRET is not configured' });

    const phone = normalizePhone(req.body?.phone);
    const code = String(req.body?.code || '');
    const record = otpStore.get(phone);

    if (!record || Date.now() > record.expiresAt) {
      otpStore.delete(phone);
      return res.status(400).json({ error: 'Код не найден или истёк. Запросите новый код' });
    }

    record.attempts += 1;
    if (record.attempts > maxAttempts) {
      otpStore.delete(phone);
      return res.status(429).json({ error: 'Превышено число попыток. Запросите новый код' });
    }

    const expectedHash = Buffer.from(record.codeHash, 'hex');
    const actualHash = Buffer.from(hashOtp(phone, code), 'hex');
    if (!/^\d{6}$/.test(code) || expectedHash.length !== actualHash.length || !crypto.timingSafeEqual(expectedHash, actualHash)) {
      return res.status(400).json({ error: 'Неверный код' });
    }

    otpStore.delete(phone);
    return res.json({ ok: true, token: createSessionToken(record.profile), profile: record.profile });
  } catch (error) {
    console.error('[Auth] Ошибка проверки OTP:', error.message);
    return res.status(500).json({ error: 'Не удалось проверить код' });
  }
});

function readSmsPayload(body) {
  const payload = body?.payload || body?.data || body;
  const phone = payload?.phone || payload?.telephone || payload?.to || payload?.phoneNumber;
  const code = payload?.token || payload?.otp || payload?.code || payload?.verificationCode;

  if (!phone || !code) {
    throw new Error('Request body must contain phone and token/code');
  }

  return { phone: String(phone), code: String(code) };
}

function toChatId(phone) {
  const normalizedPhone = String(phone).trim().replace(/^\+/, '');
  if (!/^\d+$/.test(normalizedPhone)) {
    throw new Error('Phone must contain digits with an optional leading plus');
  }
  return `${normalizedPhone}@c.us`;
}

app.post('/send-sms', async (req, res) => {
  try {
    const { phone, code } = readSmsPayload(req.body);
    const chatId = toChatId(phone);

    await axios.post(
      `${wahaUrl}/api/sendText`,
      {
        chatId,
        text: `Ваш код авторизации в R-CORE: ${code}`
      },
      {
        headers: {
          'Content-Type': 'application/json',
          ...(wahaApiKey ? { 'X-Api-Key': wahaApiKey } : {})
        },
        timeout: 10000
      }
    );

    console.info(`[WAHA] SMS отправлен: ${chatId}`);
    return res.status(200).send();
  } catch (error) {
    const details = error.response?.data || error.message;
    console.error('[WAHA] Ошибка отправки SMS:', details);
    return res.status(502).send();
  }
});

app.listen(port, '0.0.0.0', () => {
  console.info(`Custom SMS Provider listening on port ${port}`);
});
