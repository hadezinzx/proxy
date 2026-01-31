// api/webhook.js
const crypto = require('crypto');

// Configuração de destinos dos webhooks
const WEBHOOK_DESTINATIONS = {
  'service1': process.env.SERVICE1_URL,
  'service2': process.env.SERVICE2_URL,
};

// Secrets para validação de assinatura
const WEBHOOK_SECRETS = {
  'service1': process.env.SERVICE1_SECRET,
  'service2': process.env.SERVICE2_SECRET,
};

/**
 * Valida a assinatura HMAC do webhook
 */
function validateSignature(payload, signature, secret) {
  if (!signature || !secret) {
    return false;
  }

  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(JSON.stringify(payload));
  const expectedSignature = 'sha256=' + hmac.digest('hex');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  } catch {
    return false;
  }
}

/**
 * Registra eventos para auditoria
 */
function logEvent(event, data) {
  const timestamp = new Date().toISOString();
  console.log(JSON.stringify({
    timestamp,
    event,
    ...data
  }));
}

/**
 * Handler principal para Vercel
 */
export default async function handler(req, res) {
  // Apenas aceita POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método não permitido' });
  }

  // Extrai o nome do serviço da query string
  const { service } = req.query;
  const signature = req.headers['x-webhook-signature'] || req.headers['x-hub-signature-256'];

  try {
    // 1. Valida se o serviço existe
    if (!service || !WEBHOOK_DESTINATIONS[service]) {
      logEvent('webhook_error', { service, error: 'Service not found' });
      return res.status(404).json({ error: 'Serviço não encontrado' });
    }

    // 2. Valida assinatura HMAC
    const secret = WEBHOOK_SECRETS[service];
    if (secret && !validateSignature(req.body, signature, secret)) {
      logEvent('webhook_blocked', { service, reason: 'Invalid signature' });
      return res.status(401).json({ error: 'Assinatura inválida' });
    }

    // 3. Valida timestamp para prevenir replay attacks
    const timestamp = req.headers['x-webhook-timestamp'];
    if (timestamp) {
      const age = Date.now() - parseInt(timestamp);
      const MAX_AGE = 5 * 60 * 1000; // 5 minutos
      
      if (age > MAX_AGE) {
        logEvent('webhook_blocked', { service, reason: 'Request too old' });
        return res.status(400).json({ error: 'Requisição expirada' });
      }
    }

    // 4. Envia para o destino
    logEvent('webhook_forwarding', { service });
    
    const response = await fetch(WEBHOOK_DESTINATIONS[service], {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-From': 'webhook-proxy',
        'X-Original-Signature': signature || '',
      },
      body: JSON.stringify(req.body),
    });

    const responseData = await response.text();

    logEvent('webhook_success', { 
      service, 
      status: response.status 
    });

    return res.status(200).json({ 
      success: true, 
      message: 'Webhook processado com sucesso',
      destinationStatus: response.status
    });

  } catch (error) {
    logEvent('webhook_error', { 
      service, 
      error: error.message,
    });

    return res.status(500).json({ 
      error: 'Erro ao processar webhook',
      requestId: crypto.randomUUID()
    });
  }
}
