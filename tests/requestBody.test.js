const test = require('node:test');
const assert = require('node:assert/strict');
const { parseFormDataLines, normalizeRequestBodyForUpstream, formDataObjectToLines } = require('../requestBody');

test('parseFormDataLines parses key:value lines', () => {
  const parsed = parseFormDataLines('name: aman\nemail: aman@example.com');
  assert.deepEqual(parsed, [['name', 'aman'], ['email', 'aman@example.com']]);
});

test('normalizeRequestBodyForUpstream creates FormData for form-data mode', () => {
  const result = normalizeRequestBodyForUpstream({
    body: { name: 'aman', role: 'admin' },
    bodyMode: 'form-data',
    headers: { 'content-type': 'application/json', accept: 'application/json' }
  });

  assert.ok(result.body instanceof FormData);
  assert.equal(result.headers['content-type'], undefined);
  assert.equal(result.headers.accept, 'application/json');
  const fields = Object.fromEntries(result.body.entries());
  assert.deepEqual(fields, { name: 'aman', role: 'admin' });
});

test('normalizeRequestBodyForUpstream appends file in form-data mode', () => {
  const text = 'hello file';
  const result = normalizeRequestBodyForUpstream({
    body: { title: 'demo' },
    bodyMode: 'form-data',
    headers: {},
    formFiles: [
      {
        key: 'upload',
        name: 'demo.txt',
        contentType: 'text/plain',
        base64: Buffer.from(text, 'utf8').toString('base64')
      }
    ]
  });

  const filePart = result.body.get('upload');
  assert.ok(filePart instanceof File);
  assert.equal(filePart.name, 'demo.txt');
  assert.equal(filePart.type, 'text/plain');
});

test('normalizeRequestBodyForUpstream keeps raw payload as string', () => {
  const result = normalizeRequestBodyForUpstream({
    body: { amount: 1000 },
    bodyMode: 'raw',
    headers: {}
  });

  assert.equal(typeof result.body, 'string');
  assert.equal(result.headers['content-type'], 'application/json');
  assert.equal(result.body, JSON.stringify({ amount: 1000 }));
});

test('formDataObjectToLines converts object to key:value lines', () => {
  const lines = formDataObjectToLines({ user: 'aman', active: true });
  assert.equal(lines.includes('user: aman'), true);
  assert.equal(lines.includes('active: true'), true);
});
