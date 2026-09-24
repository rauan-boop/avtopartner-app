const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const port = Number(process.env.PORT || 3001);
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const wahaUrl = (process.env.WAHA_URL || '').replace(/\/$/, '');
const wahaSession = process.env.WAHA_SESSION || 'default';
const wahaApiKey = process.env.WAHA_API_KEY || '';
const otpTtlMs = 5 * 60 * 1000;
const otpStore = new Map();

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
      text: `Ваш код входа в R-Line: ${otp}. Код действителен 5 минут.`,
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

  otpStore.delete(phone);
  return res.json({ ok: true, uid: pending.uid });
});

app.listen(port, '0.0.0.0', () => {
  console.info(`Phone authorization service listening on port ${port}`);
});
