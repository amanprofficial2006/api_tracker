function parseFormDataLines(input) {
  if (Array.isArray(input)) {
    return input
      .map((item) => [String(item?.key || '').trim(), String(item?.value ?? '')])
      .filter(([key]) => Boolean(key));
  }

  if (input && typeof input === 'object') {
    return Object.entries(input).map(([key, value]) => [String(key).trim(), String(value ?? '')]).filter(([key]) => Boolean(key));
  }

  return String(input || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const idx = line.indexOf(':');
      if (idx < 0) return [line.trim(), ''];
      return [line.slice(0, idx).trim(), line.slice(idx + 1).trim()];
    })
    .filter(([key]) => Boolean(key));
}

function normalizeRequestBodyForUpstream({ body, bodyMode = 'raw', headers = {}, formFiles = [] }) {
  const normalizedMode = bodyMode === 'form-data' ? 'form-data' : 'raw';
  const normalizedHeaders = { ...(headers || {}) };

  if (normalizedMode === 'form-data') {
    const formData = new FormData();
    parseFormDataLines(body).forEach(([key, value]) => {
      formData.append(key, value);
    });
    (Array.isArray(formFiles) ? formFiles : []).forEach((fileItem) => {
      const key = String(fileItem?.key || '').trim();
      const base64 = String(fileItem?.base64 || '');
      if (!key || !base64) return;
      const fileName = String(fileItem?.name || 'upload.bin');
      const contentType = String(fileItem?.contentType || 'application/octet-stream');
      const bytes = Buffer.from(base64, 'base64');
      const blob = new Blob([bytes], { type: contentType });
      formData.append(key, blob, fileName);
    });
    delete normalizedHeaders['content-type'];
    return { body: formData, headers: normalizedHeaders };
  }

  const nextBody = typeof body === 'string' ? body : JSON.stringify(body);
  if (!normalizedHeaders['content-type'] && typeof nextBody === 'string') {
    normalizedHeaders['content-type'] = 'application/json';
  }
  return { body: nextBody, headers: normalizedHeaders };
}

function formDataObjectToLines(value) {
  return parseFormDataLines(value).map(([key, itemValue]) => `${key}: ${itemValue}`).join('\n');
}

function formFilesToLines(value) {
  return (Array.isArray(value) ? value : [])
    .map((item) => {
      const key = String(item?.key || '').trim();
      const name = String(item?.name || 'upload.bin');
      return key ? `${key}: [file] ${name}` : '';
    })
    .filter(Boolean)
    .join('\n');
}

module.exports = {
  parseFormDataLines,
  normalizeRequestBodyForUpstream,
  formDataObjectToLines,
  formFilesToLines
};
