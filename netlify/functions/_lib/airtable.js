// netlify/functions/_lib/airtable.js
// Server-side Airtable REST helper. Used by admin-* functions to talk to
// Airtable directly with the server-only AIRTABLE_TOKEN — this never touches
// the browser. (Distinct from the public netlify/functions/airtable.js proxy,
// which is intentionally locked down for candidate-facing use only.)

/**
 * Low-level Airtable REST call.
 * @param {string} table  Table name (e.g. "Admins")
 * @param {string} method GET | POST | PATCH | DELETE
 * @param {object|null} body Request body (will be JSON-stringified)
 * @param {string} id Optional record id, appended as its own path segment
 * @param {string} qs Optional query string WITHOUT leading "?"
 */
async function airtableRequest(table, method = 'GET', body = null, id = '', qs = '') {
  const TOKEN = process.env.AIRTABLE_TOKEN;
  const BASE_ID = process.env.AIRTABLE_BASE_ID;
  if (!TOKEN || !BASE_ID) {
    throw new Error('Server not configured: AIRTABLE_TOKEN / AIRTABLE_BASE_ID missing.');
  }
  // Encode table and id as SEPARATE segments (see the public proxy's comment —
  // encoding "table/id" as one string turns "/" into "%2F" and silently breaks
  // every request against a specific record).
  const recordPath = id
    ? encodeURIComponent(table) + '/' + encodeURIComponent(id)
    : encodeURIComponent(table);
  const url = `https://api.airtable.com/v0/${BASE_ID}/${recordPath}${qs ? '?' + qs : ''}`;

  const opts = {
    method,
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      'Content-Type': 'application/json',
    },
  };
  if (body) {
    if (method === 'POST' || method === 'PATCH') body.typecast = true;
    opts.body = JSON.stringify(body);
  }

  const r = await fetch(url, opts);
  const text = await r.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { error: { message: 'Non-JSON response from Airtable' } };
  }
  if (!r.ok) {
    const msg = data?.error?.message || r.statusText;
    const err = new Error(`Airtable ${method} ${table} failed: ${msg}`);
    err.status = r.status;
    err.airtableError = data.error;
    throw err;
  }
  return data;
}

/** Convenience: list ALL records of a table (auto-paginates), optionally filtered. */
async function airtableListAll(table, filterFormula = null, extraQs = '') {
  const records = [];
  let offset = null;
  do {
    const parts = ['pageSize=100'];
    if (filterFormula) parts.push('filterByFormula=' + encodeURIComponent(filterFormula));
    if (extraQs) parts.push(extraQs);
    if (offset) parts.push('offset=' + encodeURIComponent(offset));
    const data = await airtableRequest(table, 'GET', null, '', parts.join('&'));
    records.push(...(data.records || []));
    offset = data.offset || null;
  } while (offset);
  return records;
}

module.exports = { airtableRequest, airtableListAll };
