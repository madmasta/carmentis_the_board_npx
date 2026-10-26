// C-UPLOAD-1 proof file (docs/03 "Files, network, XML, commands").
//
// The upload rules live in src/hooks/upload.js; the size cap lives in the
// request parser, so one case here drives the parser with an oversized part to
// prove the cap fires before any handler could look at the file.

import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import {
  UPLOAD_TYPES,
  UNSUPPORTED_MESSAGE,
  inspect,
  isStoredName,
  readStored,
  resolveStored,
  store,
  storedSize,
  typeOfStored,
  uploadsDir,
} from '../../src/hooks/upload.js';
import { MAX_UPLOAD_BYTES, parse } from '../../src/http/request.js';

const SIGNATURES = {
  'image/png': Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from(' ihdr')]),
  'image/jpeg': Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.from(' jfif')]),
  'image/gif': Buffer.concat([Buffer.from('GIF89a', 'latin1'), Buffer.from(' data')]),
  'image/webp': Buffer.concat([Buffer.from('RIFF', 'latin1'), Buffer.from([0x10, 0, 0, 0]), Buffer.from('WEBP', 'latin1')]),
};

function filePart({ filename, mimeType, buffer }) {
  return { field: 'avatar', filename, mimeType, size: buffer.length, buffer };
}

function multipartRequest(body, boundary) {
  const req = Readable.from([body]);
  req.method = 'POST';
  req.url = '/profile/avatar';
  req.headers = {
    'content-type': `multipart/form-data; boundary=${boundary}`,
    'content-length': String(Buffer.byteLength(body)),
    host: 'localhost:8088',
  };
  req.socket = { remoteAddress: '127.0.0.1' };
  return req;
}

describe('avatar upload (C-UPLOAD-1)', () => {
  it('accepts each allowlisted type when magic bytes and MIME agree', () => {
    for (const type of UPLOAD_TYPES) {
      const file = filePart({ filename: `photo.${type.ext}`, mimeType: type.mime, buffer: SIGNATURES[type.mime] });
      const result = inspect(file);
      expect(result.ok).toBe(true);
      expect(result.type.mime).toBe(type.mime);
    }
  });

  it('c-upload-1 rejects a php payload hidden in the filename', () => {
    // Real PNG bytes, but the name is trying to buy a second extension.
    const file = filePart({ filename: 'shell.php.png', mimeType: 'image/png', buffer: SIGNATURES['image/png'] });
    expect(inspect(file)).toEqual({ ok: false, message: UNSUPPORTED_MESSAGE });
  });

  it('c-upload-1 rejects an svg', () => {
    const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', 'utf8');
    for (const mime of ['image/svg+xml', 'image/png', 'text/plain']) {
      expect(inspect(filePart({ filename: 'diagram.svg', mimeType: mime, buffer: svg })).ok).toBe(false);
    }
  });

  it('c-upload-1 rejects a double extension', () => {
    const file = filePart({ filename: 'avatar.png.php', mimeType: 'image/png', buffer: SIGNATURES['image/png'] });
    expect(inspect(file).ok).toBe(false);
  });

  it('c-upload-1 rejects a type whose magic bytes disagree with the MIME type', () => {
    // A GIF renamed to .png, and PHP text declared as a PNG.
    expect(inspect(filePart({ filename: 'x.png', mimeType: 'image/png', buffer: SIGNATURES['image/gif'] })).ok).toBe(false);
    const php = Buffer.from('<?php system($_GET["c"]); ?>', 'utf8');
    expect(inspect(filePart({ filename: 'x.png', mimeType: 'image/png', buffer: php })).ok).toBe(false);
  });

  it('c-upload-1 an oversized part is refused by the parser, before the handler', async () => {
    const boundary = 'uploadcap';
    const payload = Buffer.concat([SIGNATURES['image/png'], Buffer.alloc(MAX_UPLOAD_BYTES + 1, 0x41)]);
    const body = Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="avatar"; filename="big.png"\r\nContent-Type: image/png\r\n\r\n`, 'utf8'),
      payload,
      Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8'),
    ]);

    await expect(parse(multipartRequest(body, boundary))).rejects.toMatchObject({
      status: 400,
      message: 'File is too large',
    });
    expect(MAX_UPLOAD_BYTES).toBe(2 * 1024 * 1024);
  });

  it('c-upload-1 stores under a generated name, never the client filename', () => {
    const file = filePart({
      filename: '../../../../etc/shadow.png',
      mimeType: 'image/png',
      buffer: SIGNATURES['image/png'],
    });
    // The traversal is not what is rejected; what matters is that no path is ever
    // built from it: the name on disk is a UUID this app chose.
    const name = store(file, inspect({ ...file, filename: 'ok.png' }).type);
    expect(isStoredName(name)).toBe(true);
    expect(name).not.toContain('..');
    expect(name).not.toContain('shadow');
    expect(storedSize(name)).toBe(SIGNATURES['image/png'].length);
    expect(readStored(name)).toEqual(SIGNATURES['image/png']);
  });

  it('c-upload-1 resolves nothing but a generated name', () => {
    for (const name of [
      '../../etc/passwd',
      '../../etc/passwd.png',
      'a/../b.png',
      '%2e%2e%2f%2e%2e%2fetc',
      '/etc/passwd.png',
      'uuid.png.php',
      'not-a-uuid.png',
      '',
      null,
      undefined,
    ]) {
      expect(resolveStored(name)).toBeNull();
      expect(readStored(name)).toBeNull();
    }
  });

  it('c-upload-1 serves only the allowlisted content type for a stored name', () => {
    expect(typeOfStored('11111111-2222-3333-4444-555555555555.png').mime).toBe('image/png');
    expect(typeOfStored('11111111-2222-3333-4444-555555555555.php')).toBeNull();
  });

  it('uploads live outside the web root', () => {
    const dir = uploadsDir().replace(/\\/g, '/');
    expect(dir).toContain('/var/uploads');
    expect(dir).not.toContain('/public/');
  });
});
