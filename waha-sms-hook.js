const express = require('express');
const axios = require('axios');

const app = express();
const port = Number(process.env.PORT || 3003);
const wahaUrl = process.env.WAHA_URL || 'http://localhost:3000';
const wahaSession = process.env.WAHA_SESSION || 'default';
const wahaApiKey = process.env.WAHA_API_KEY || '';

app.use(express.json({ limit: '1mb' }));

function readOtpPayload(body) {
  const payload = body?.payload || body?.data || body;
  const phone = payload?.phone || payload?.telephone || payload?.to || payload?.phoneNumber;
  const code = payload?.token || payload?.otp || payload?.code || payload?.verificationCode;

  if (!phone || !code) {
    throw new Error('Webhook payload must contain phone and token/code');
  }

  return {
    phone: String(phone),
    code: String(code)
  };
}

function toWahaChatId(phone) {
  const digits = phone.replace(/\D/g, '');
  const normalized = digits.startsWith('8') ? `7${digits.slice(1)}` : digits;
  return normalized.endsWith('@c.us') ? normalized : `${normalized}@c.us`;
}

app.post('/webhook/sms', async (req, res) => {
  try {
    const { phone, code } = readOtpPayload(req.body);
    const chatId = toWahaChatId(phone);
    const text = `Код авторизации R-CORE: ${code}`;

    await axios.post(
      `${wahaUrl}/api/sendText`,
      {
        session: wahaSession,
        chatId,
        text
      },
      {
        headers: {
          'Content-Type': 'application/json',
          ...(wahaApiKey ? { 'X-Api-Key': wahaApiKey } : {})
        },
        timeout: 10000
      }
    );

    console.info(`[WAHA] OTP отправлен: ${chatId}`);
    return res.sendStatus(200);
  } catch (error) {
    const status = error.response?.status;
    const details = error.response?.data || error.message;
    console.error('[WAHA] Ошибка отправки OTP:', status || '', details);

    // Supabase должен повторить webhook, если WAHA временно недоступен.
    return res.status(502).json({
      error: 'WAHA delivery failed'
    });
  }
});

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.listen(port, '0.0.0.0', () => {
  console.info(`WAHA SMS hook listening on port ${port}`);
});
