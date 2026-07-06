import { env, isDeepSeekConfigured } from '../config/env.js';

const systemPrompt = [
  'You are DepositFree Agent, a concise assistant for a Stellar stablecoin protection dashboard.',
  'Help users understand app flows, stablecoin loss protection concepts, and payment draft preparation.',
  'Do not claim payouts are guaranteed.',
  'Do not give financial advice.',
  'Do not invent wallet addresses, usernames, balances, contract addresses, or transaction hashes.',
  'If the user asks to send money, explain that the app can prepare a reviewable draft but cannot execute a payment without wallet signing.',
].join(' ');

export class DeepSeekConfigurationError extends Error {
  constructor() {
    super('DEEPSEEK_API_KEY is not configured on the server.');
    this.name = 'DeepSeekConfigurationError';
    this.statusCode = 503;
  }
}

export class DeepSeekProviderError extends Error {
  constructor(message, statusCode = 502) {
    super(message);
    this.name = 'DeepSeekProviderError';
    this.statusCode = statusCode;
  }
}

export async function createDeepSeekReply(userMessage) {
  if (!isDeepSeekConfigured()) {
    throw new DeepSeekConfigurationError();
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), env.deepseek.timeoutMs);

  try {
    const apiResponse = await fetch(`${env.deepseek.baseUrl}/chat/completions`, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${env.deepseek.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: env.deepseek.model,
        temperature: env.deepseek.temperature,
        max_tokens: env.deepseek.maxTokens,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userMessage },
        ],
      }),
    });

    const data = await apiResponse.json().catch(() => null);

    if (!apiResponse.ok) {
      throw new DeepSeekProviderError(data?.error?.message || 'DeepSeek request failed.', apiResponse.status);
    }

    return data?.choices?.[0]?.message?.content?.trim() || 'No response returned.';
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new DeepSeekProviderError('DeepSeek request timed out.', 504);
    }

    if (error instanceof DeepSeekConfigurationError || error instanceof DeepSeekProviderError) {
      throw error;
    }

    throw new DeepSeekProviderError(error.message || 'DeepSeek request failed.');
  } finally {
    clearTimeout(timeout);
  }
}
