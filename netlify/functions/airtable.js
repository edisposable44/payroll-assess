// netlify/functions/airtable.js
// Serverless proxy: hides the Airtable token from the browser entirely.
// Both the recruiter AND the applicant call THIS function — never Airtable directly.
//
// Required environment variables (Netlify: Site settings → Environment variables):
//   AIRTABLE_TOKEN    → your Airtable Personal Access Token
//   AIRTABLE_BASE_ID  → your Airtable Base ID (starts with "app")

exports.handler = async function (event) {
  const TOKEN = process.env.AIRTABLE_TOKEN;
  const BASE_ID = process.env.AIRTABLE_BASE_ID;

  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: cors, body: '' };
  }

  if (!TOKEN || !BASE_ID) {
    return {
      statusCode: 500,
      headers: cors,
      body: JSON.stringify({ error: { message: 'Server not configured: set AIRTABLE_TOKEN and AIRTABLE_BASE_ID in Netlify environment variables.' } })
    };
  }

  const params = event.queryStringParameters || {};
  const table = params.table;   // e.g. "Sessions"
  const id = params.id;         // optional record id, e.g. "recXXXXXXXXXXXXXX"
  const qs = params.qs || '';   // e.g. "maxRecords=200&sort[0][field]=..."

  if (!table) {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: { message: 'Missing "table" query parameter' } }) };
  }

  // Encode EACH path segment separately so the "/" between table and record id
  // stays a real path separator instead of being escaped to %2F (which breaks
  // every PATCH/GET-by-id request against Airtable).
  const recordPath = id
    ? encodeURIComponent(table) + '/' + encodeURIComponent(id)
    : encodeURIComponent(table);

  const url = `https://api.airtable.com/v0/${BASE_ID}/${recordPath}${qs ? '?' + qs : ''}`;

  const opts = {
    method: event.httpMethod,
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      'Content-Type': 'application/json'
    }
  };
  if (event.body) opts.body = event.body;

  try {
    const r = await fetch(url, opts);
    const data = await r.text();
    return { statusCode: r.status, headers: { ...cors, 'Content-Type': 'application/json' }, body: data };
  } catch (e) {
    return { statusCode: 502, headers: cors, body: JSON.stringify({ error: { message: 'Upstream Airtable request failed: ' + e.message } }) };
  }
};
