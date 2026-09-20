const express = require('express');
const axios = require('axios');
const app = express();
const port = Number(process.env.PORT || 3001);
const wahaUrl = process.env.WAHA_URL || 'http://localhost:3000';
const wahaApiKey = process.env.WAHA_API_KEY || '';

app.use(express.json());

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
