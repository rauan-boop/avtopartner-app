const express = require('express');
const axios = require('axios');

const app = express();
const port = Number(process.env.PORT || 3001);
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

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

  const requestConfig = {
    headers: {
      apikey: supabaseServiceRoleKey,
      Authorization: `Bearer ${supabaseServiceRoleKey}`
    },
    timeout: 10000
  };

  const normalizedPhone = normalizePhone(phone);
  for (let page = 1; page <= 10; page += 1) {
    const response = await axios.get(`${supabaseUrl}/auth/v1/admin/users`, {
      ...requestConfig,
      params: { page, per_page: 1000 }
    });
    const users = response.data?.users || [];
    const user = users.find(item => normalizePhone(item.phone) === normalizedPhone);
    if (user) {
      return {
        id: user.id,
        phone: user.phone,
        email: user.email,
        role: user.role,
        created_at: user.created_at
      };
    }
    if (users.length < 1000) break;
  }

  return null;
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

    return res.json({ ok: true, profile: user });
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
    if (upstreamStatus) {
      return res.status(502).json({ error: `Supabase Authentication API вернул HTTP ${upstreamStatus}` });
    }
    return res.status(502).json({ error: `Не удалось подключиться к Supabase Authentication API (${networkCode})` });
  }
});

app.listen(port, '0.0.0.0', () => {
  console.info(`Phone authorization service listening on port ${port}`);
});
