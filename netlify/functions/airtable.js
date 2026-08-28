// netlify/functions/airtable.js
// PUBLIC proxy — reachable by any candidate browser, no authentication.
// Scope is deliberately locked down to exactly what the candidate quiz flow
// needs, and nothing more:
//
//   Sessions   GET   — MUST include a filterByFormula in `qs` (looking up a
//                       session by its own PIN). Un-filtered listing of every
//                       session is refused, so a candidate can't dump the
//                       whole roster.
//   Sessions   PATCH — update the candidate's OWN session by id (status
//                       transitions: ouverte → en_cours → terminee).
//   Resultats  POST  — create the candidate's OWN result at the end of the quiz.
//
// Everything else (listing all results/scores, editing the question bank,
// admin session management) is refused here — those live behind
// admin-data.js, which requires a signed session token.
//
// Required environment variables (Netlify: Site settings → Environment variables):
//   AIRTABLE_TOKEN    → your Airtable Personal Access Token
//   AIRTABLE_BASE_ID  → your Airtable Base ID (starts with "app")

const { airtableRequest } = require('./_lib/airtable');

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };

  const params = event.queryStringParameters || {};
  const table = params.table;
  const id = params.id || '';
  const qs = params.qs || '';
  const method = event.httpMethod;

  if (!table) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: { message: 'Missing "table" query parameter' } }) };
  }

  // ── Scope enforcement ────────────────────────────────────────────────────
  if (table === 'Sessions') {
    if (method === 'GET') {
      if (!qs.includes('filterByFormula=')) {
        return {
          statusCode: 403,
          headers: CORS,
          body: JSON.stringify({ error: { message: 'Unfiltered Sessions listing is not permitted on the public endpoint.' } }),
        };
      }
    } else if (method !== 'PATCH') {
      return { statusCode: 403, headers: CORS, body: JSON.stringify({ error: { message: `Method ${method} not permitted on Sessions here.` } }) };
    }
  } else if (table === 'Resultats') {
    if (method !== 'POST') {
      return { statusCode: 403, headers: CORS, body: JSON.stringify({ error: { message: 'Only creating a result is permitted here (no listing).' } }) };
    }
  } else {
    return { statusCode: 403, headers: CORS, body: JSON.stringify({ error: { message: `Table "${table}" is not accessible via the public endpoint.` } }) };
  }

  let body = null;
  if (event.body) {
    try {
      body = JSON.parse(event.body);
    } catch {
      return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: { message: 'Invalid JSON body' } }) };
    }
  }

  try {
    const data = await airtableRequest(table, method, body, id, qs);
    return { statusCode: 200, headers: { ...CORS, 'Content-Type': 'application/json' }, body: JSON.stringify(data) };
  } catch (e) {
    return { statusCode: e.status || 500, headers: CORS, body: JSON.stringify({ error: { message: e.message } }) };
  }
};
