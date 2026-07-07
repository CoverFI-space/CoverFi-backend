import { env, isDeepSeekConfigured } from '../config/env.js';

const baseSystemPrompt = [
  'You are CoverFi AI, a concise assistant for CoverFi, a Stellar stablecoin protection dashboard.',
  'The website and product name is CoverFi. Use CoverFi consistently in user-facing responses.',
  'Help users understand CoverFi app flows, stablecoin loss protection concepts, and payment draft preparation.',
  'Format every response as clean GitHub-flavored Markdown, like a short README section.',
  'Use headings, short paragraphs, bullets, numbered steps, and tables only when they make the answer easier to scan.',
  'For payment drafts, use a heading such as "Payment Draft", then list recipient, asset, amount, fee, total, memo, and signing status.',
  'Do not claim payouts are guaranteed.',
  'Do not give financial advice.',
  'Do not invent wallet addresses, usernames, balances, contract addresses, or transaction hashes.',
  'If the user asks to send money, explain that the app can prepare a reviewable draft but cannot execute a payment without wallet signing.',
].join(' ');

function compactJson(value) {
  if (!value) return '';

  try {
    return JSON.stringify(value, null, 2).slice(0, 6000);
  } catch {
    return '';
  }
}

function buildSystemPrompt({ mode = 'chat', accountContext, marketContext } = {}) {
  const sections = [baseSystemPrompt];

  if (mode === 'research') {
    sections.push(
      [
        'Research mode is enabled.',
        'Use the deepseek-research model response style: compare, verify, and separate known app data from broader research.',
        'If external information is unavailable from the model context, say what you can infer and what should be verified.',
      ].join(' '),
    );
  }

  const account = compactJson(accountContext);
  if (account) {
    sections.push(`User/app context JSON:\n${account}`);
  }

  const markets = compactJson(marketContext);
  if (markets) {
    sections.push(`Live market context JSON:\n${markets}`);
  }

  return sections.join('\n\n');
}

function isSafeModelName(value) {
  return /^[a-zA-Z0-9._:-]{1,80}$/.test(String(value || ''));
}

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

export async function createDeepSeekReply(userMessage, options = {}) {
  if (!isDeepSeekConfigured()) {
    throw new DeepSeekConfigurationError();
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), env.deepseek.timeoutMs);
  const mode = options.mode === 'research' ? 'research' : 'chat';
  const fallbackModel = mode === 'research' ? env.deepseek.researchModel : env.deepseek.model;
  const model = isSafeModelName(options.model) ? options.model : fallbackModel;

  try {
    const apiResponse = await fetch(`${env.deepseek.baseUrl}/chat/completions`, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${env.deepseek.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model,
        temperature: env.deepseek.temperature,
        max_tokens: env.deepseek.maxTokens,
        messages: [
          { role: 'system', content: buildSystemPrompt(options) },
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
