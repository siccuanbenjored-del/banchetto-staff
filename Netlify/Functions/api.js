
exports.handler = async function (event) {
  const allowedOrigin = process.env.ALLOWED_ORIGIN || '';
  const origin = event.headers.origin || event.headers.Origin || '';

  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
    'Cache-Control': 'no-store'
  };

  if (!allowedOrigin || origin !== allowedOrigin) {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Origin not allowed.'
      })
    };
  }

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'POST required.'
      })
    };
  }

  try {
    const gasUrl = process.env.GAS_WEB_APP_URL;
    const apiSecret = process.env.GAS_API_SECRET;

    if (!gasUrl || !apiSecret) {
      throw new Error('Server environment variables are missing.');
    }

    if (!/^https:\/\/script\.google\.com\/macros\/s\/[^/]+\/exec$/.test(gasUrl)) {
      throw new Error('GAS_WEB_APP_URL must be a deployed Apps Script /exec URL.');
    }

    let request;
    try {
      request = JSON.parse(event.body || '{}');
    } catch (error) {
      throw new Error('Invalid JSON request.');
    }

    const actions = ['login', 'lookup', 'update'];
    if (!actions.includes(String(request.action || ''))) {
      throw new Error('Invalid API action.');
    }

    const ip =
      event.headers['x-nf-client-connection-ip'] ||
      event.headers['client-ip'] ||
      'unknown';

    // Never trust a secret supplied by the browser.
    const payload = {
      ...request,
      apiSecret: apiSecret,
      clientIp: ip
    };

    const form = new URLSearchParams();
    form.set('payload', JSON.stringify(payload));

    const response = await fetch(gasUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
      },
      body: form.toString(),
      redirect: 'follow'
    });

    const text = await response.text();

    let result;
    try {
      result = JSON.parse(text);
    } catch (error) {
      throw new Error(
        'Apps Script did not return JSON. Check the deployed web app URL and access settings.'
      );
    }

    // Apps Script reports application errors inside its JSON response.
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(result)
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: error.message || 'Server error.'
      })
    };
  }
};
