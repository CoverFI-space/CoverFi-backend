import { env } from '../config/env.js';

function fail(message, code = 1) {
  console.error(message);
  process.exitCode = code;
}

async function readJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

if (!env.onboarding.resendApiKey) {
  fail('RESEND_API_KEY is missing in server/.env.');
  throw new Error('missing_resend_api_key');
}

console.log(JSON.stringify({
  provider: 'resend',
  from: env.onboarding.emailFrom,
  hasApiKey: true,
}, null, 2));

const domainsResponse = await fetch('https://api.resend.com/domains', {
  headers: {
    Authorization: `Bearer ${env.onboarding.resendApiKey}`,
  },
});
const domains = await readJson(domainsResponse);

if (!domainsResponse.ok) {
  const message = String(domains.message || domains.raw || '');
  if (/restricted to only send emails/i.test(message)) {
    console.log(JSON.stringify({
      ok: true,
      step: 'domains',
      warning: 'This Resend API key is send-only, so domain listing is not allowed. Use the optional send test to verify delivery.',
    }, null, 2));
  } else {
    fail(JSON.stringify({
      ok: false,
      step: 'domains',
      status: domainsResponse.status,
      message: domains.message || domains.raw || 'Resend domain check failed.',
    }, null, 2));
    throw new Error('resend_domain_check_failed');
  }
} else {
  console.log(JSON.stringify({
    ok: true,
    step: 'domains',
    count: Array.isArray(domains.data) ? domains.data.length : undefined,
    domains: Array.isArray(domains.data)
      ? domains.data.map((domain) => ({
          name: domain.name,
          status: domain.status,
          region: domain.region,
        }))
      : domains,
  }, null, 2));
}

const to = process.argv[2] || process.env.RESEND_TEST_TO || '';
if (!to) {
  console.log('Pass an email to send a live test: npm --prefix server run email:verify -- you@example.com');
} else {
  const sendResponse = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.onboarding.resendApiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.onboarding.emailFrom,
      to: [to],
      subject: 'CoverFi Resend test',
      text: 'Resend delivery is configured for CoverFi OTP email.',
      html: '<p>Resend delivery is configured for CoverFi OTP email.</p>',
    }),
  });
  const send = await readJson(sendResponse);

  if (!sendResponse.ok) {
    fail(JSON.stringify({
      ok: false,
      step: 'send',
      status: sendResponse.status,
      message: send.message || send.raw || 'Resend test send failed.',
    }, null, 2));
  } else {
    console.log(JSON.stringify({
      ok: true,
      step: 'send',
      id: send.id,
      to,
    }, null, 2));
  }
}
