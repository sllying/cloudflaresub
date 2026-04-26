// Cloudflare Worker: KV short link subscription + access token protection
// Requires:
// - KV namespace binding: SUB_STORE
// - Secret/Variable: SUB_ACCESS_TOKEN
// Optional:
// - Secret/Variable: SUB_LINK_SECRET (legacy long-token compatibility)
import {
  expandNodes as coreExpandNodes,
  parseNodeLinks as coreParseNodeLinks,
  parsePreferredEndpoints as coreParsePreferredEndpoints,
  renderClashSubscription as coreRenderClashSubscription,
  renderRawSubscription as coreRenderRawSubscription,
  renderSurgeSubscription as coreRenderSurgeSubscription,
  summarizeNodes as coreSummarizeNodes,
} from './core.js';

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type',
    },
  });
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'access-control-allow-origin': '*',
    },
  });
}

function b64EncodeUtf8(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function b64DecodeUtf8(str) {
  return decodeURIComponent(escape(atob(str)));
}

function escapeYaml(str = '') {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, ' ');
}

function parsePreferredEndpoints(input) {
  return String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [raw, remark = ''] = line.split('#');
      const value = raw.trim();
      const hashRemark = remark.trim();
      const match = value.match(/^(.*?)(?::(\d+))?$/);
      return {
        server: match?.[1] || value,
        port: match?.[2] ? Number(match[2]) : undefined,
        remark: hashRemark,
      };
    });
}

function parseVmess(link) {
  const raw = link.slice('vmess://'.length).trim();
  const obj = JSON.parse(b64DecodeUtf8(raw));
  return {
    type: 'vmess',
    name: obj.ps || 'vmess',
    server: obj.add,
    port: Number(obj.port || 443),
    uuid: obj.id,
    cipher: obj.scy || 'auto',
    network: obj.net || 'ws',
    tls: obj.tls === 'tls',
    host: obj.host || '',
    path: obj.path || '/',
    sni: obj.sni || obj.host || '',
    alpn: obj.alpn || '',
    fp: obj.fp || '',
  };
}

function parseUrlLike(link, type) {
  const u = new URL(link);
  const params = Object.fromEntries(u.searchParams.entries());
  const security = String(params.security || '').toLowerCase();
  return {
    type,
    name: decodeURIComponent(u.hash.replace(/^#/, '')) || type,
    server: u.hostname,
    port: Number(u.port || 443),
    password: type === 'trojan' ? decodeURIComponent(u.username) : undefined,
    uuid: type === 'vless' ? decodeURIComponent(u.username) : undefined,
    network: params.type || 'tcp',
    tls: security === 'tls' || security === 'reality' || security === 'xtls',
    security,
    host: params.host || params.sni || '',
    path: params.path || '/',
    sni: params.sni || params.host || '',
    fp: params.fp || '',
    alpn: params.alpn || '',
    flow: params.flow || '',
    params,
  };
}

function parseRawLinks(input) {
  const text = String(input || '').trim();
  if (!text) {
    return [];
  }
  return coreParseNodeLinks(text).nodes.map(normalizeStoredNode);
}

function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = (options.namePrefix || '').trim();
  let counter = 0;
  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter += 1;
      const nameParts = [];
      if (node.name) nameParts.push(node.name);
      if (prefix) nameParts.push(prefix);
      if (ep.remark) nameParts.push(ep.remark);
      else nameParts.push(String(counter));
      output.push({
        ...node,
        name: nameParts.join(' | '),
        server: ep.server,
        port: ep.port || node.port,
        host: options.keepOriginalHost ? node.host : '',
        sni: options.keepOriginalHost ? node.sni : '',
      });
    }
  }
  return output;
}

function ensureUniqueNodeNames(nodes) {
  const seen = new Map();
  return nodes.map((node) => {
    const baseName = String(node.name || 'node').trim() || 'node';
    const count = (seen.get(baseName) || 0) + 1;
    seen.set(baseName, count);

    if (count === 1) {
      return {
        ...node,
        name: baseName,
      };
    }

    return {
      ...node,
      name: `${baseName} | ${count}`,
    };
  });
}

function encodeVmess(node) {
  const obj = {
    v: '2',
    ps: node.name,
    add: node.server,
    port: String(node.port),
    id: node.uuid,
    aid: '0',
    scy: node.cipher || 'auto',
    net: node.network || 'ws',
    type: 'none',
    host: node.host || '',
    path: node.path || '/',
    tls: node.tls ? 'tls' : '',
    sni: node.sni || '',
    alpn: node.alpn || '',
    fp: node.fp || '',
  };
  return 'vmess://' + b64EncodeUtf8(JSON.stringify(obj));
}

function encodeVless(node) {
  const url = new URL(`vless://${encodeURIComponent(node.uuid)}@${node.server}:${node.port}`);
  const params = new URLSearchParams(node.params || {});
  params.set('type', node.network || 'ws');
  if (node.security) params.set('security', node.security);
  else if (node.tls) params.set('security', 'tls');
  else params.delete('security');
  if (node.host) params.set('host', node.host);
  else params.delete('host');
  if (node.sni) params.set('sni', node.sni);
  else params.delete('sni');
  if (node.path) params.set('path', node.path);
  else params.delete('path');
  if (node.alpn) params.set('alpn', node.alpn);
  else params.delete('alpn');
  if (node.fp) params.set('fp', node.fp);
  else params.delete('fp');
  if (node.flow) params.set('flow', node.flow);
  else params.delete('flow');
  url.search = params.toString();
  url.hash = node.name;
  return url.toString();
}

function encodeTrojan(node) {
  const url = new URL(`trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}`);
  const params = new URLSearchParams(node.params || {});
  if (node.network) params.set('type', node.network);
  else params.delete('type');
  if (node.security) params.set('security', node.security);
  else if (node.tls) params.set('security', 'tls');
  else params.delete('security');
  if (node.host) params.set('host', node.host);
  else params.delete('host');
  if (node.sni) params.set('sni', node.sni);
  else params.delete('sni');
  if (node.path) params.set('path', node.path);
  else params.delete('path');
  if (node.alpn) params.set('alpn', node.alpn);
  else params.delete('alpn');
  if (node.fp) params.set('fp', node.fp);
  else params.delete('fp');
  url.search = params.toString();
  url.hash = node.name;
  return url.toString();
}

function renderRaw(nodes) {
  return coreRenderRawSubscription(nodes.map(normalizeStoredNode));
}

function renderClash(nodes) {
  return coreRenderClashSubscription(nodes.map(normalizeStoredNode));
}

function renderSurge(nodes, baseUrl, accessToken) {
  const requestUrl = accessToken ? `${baseUrl}?token=${encodeURIComponent(accessToken)}` : baseUrl;
  return coreRenderSurgeSubscription(nodes.map(normalizeStoredNode), requestUrl);
}

function normalizeStoredNode(node = {}) {
  const security = String(node.security || (node.tls ? 'tls' : '')).trim().toLowerCase();
  const alpn = Array.isArray(node.alpn)
    ? node.alpn
    : String(node.alpn || '')
        .split(/[\n,]+/)
        .map((item) => item.trim())
        .filter(Boolean);

  return {
    ...node,
    name: String(node.name || node.ps || 'node').trim() || 'node',
    server: String(node.server || node.add || '').trim(),
    originalServer: String(node.originalServer || node.server || node.add || '').trim(),
    port: Number(node.port || 443),
    network: String(node.network || node.net || 'tcp').trim() || 'tcp',
    path: String(node.path || '/').trim() || '/',
    hostHeader: String(node.hostHeader || node.host || '').trim(),
    host: String(node.host || node.hostHeader || '').trim(),
    sni: String(node.sni || node.hostHeader || node.host || '').trim(),
    tls: Boolean(node.tls || security === 'tls' || security === 'reality' || security === 'xtls'),
    security,
    alpn,
    fp: String(node.fp || '').trim(),
    flow: String(node.flow || '').trim(),
    serviceName: String(node.serviceName || '').trim(),
    authority: String(node.authority || '').trim(),
    encryption: String(node.encryption || 'none').trim() || 'none',
    allowInsecure: Boolean(node.allowInsecure),
    params: { ...(node.params || {}) },
  };
}

function createShortId(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}

async function createUniqueShortId(env, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const id = createShortId(10);
    const exists = await env.SUB_STORE.get(`sub:${id}`);
    if (!exists) return id;
  }
  throw new Error('无法生成唯一短链接，请稍后再试');
}

function normalizeCustomShortId(value = '') {
  const id = String(value || '').trim();
  if (!id) return '';
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(id)) {
    throw new Error('固定订阅标识仅支持 4-64 位字母、数字、下划线和连字符');
  }
  return id;
}

function normalizeLines(value = '') {
  return String(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .sort()
    .join('\n');
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function buildDedupHash(body) {
  const normalized = {
    nodeLinks: normalizeLines(body.nodeLinks || ''),
    preferredIps: normalizeLines(body.preferredIps || ''),
    appendNodeLinks: normalizeLines(body.appendNodeLinks || ''),
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  return sha256Hex(JSON.stringify(normalized));
}

async function handleGenerate(request, env, url) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
  }

  let baseParsed;
  let appendParsed;
  let preferredParsed;
  try {
    baseParsed = coreParseNodeLinks(body.nodeLinks || '');
    appendParsed = body.appendNodeLinks ? coreParseNodeLinks(body.appendNodeLinks) : { nodes: [], warnings: [] };
    preferredParsed = coreParsePreferredEndpoints(body.preferredIps || '');
  } catch (error) {
    return json({ ok: false, error: error.message || '输入解析失败' }, 400);
  }

  const baseNodes = baseParsed.nodes.map(normalizeStoredNode);
  const appendNodes = appendParsed.nodes.map(normalizeStoredNode);
  const preferredEndpoints = preferredParsed.endpoints;

  const options = {
    namePrefix: body.namePrefix || '',
    keepOriginalHost: body.keepOriginalHost !== false,
  };

  let customShortId = '';
  try {
    customShortId = normalizeCustomShortId(body.customShortId || '');
  } catch (error) {
    return json({ ok: false, error: error.message || '固定订阅标识不合法' }, 400);
  }

  const expanded = coreExpandNodes(baseNodes, preferredEndpoints, options);
  const preferredNodes = expanded.nodes.map(normalizeStoredNode);
  const nodes = ensureUniqueNodeNames([...preferredNodes, ...appendNodes]);
  if (!nodes.length) {
    return json({ ok: false, error: '请至少填写 1 个节点链接或追加节点。' }, 400);
  }

  const payload = {
    version: 1,
    createdAt: new Date().toISOString(),
    options,
    nodes,
  };

  const dedupHash = await buildDedupHash(body);
  const dedupKey = `dedup:${dedupHash}`;

  const ttl = 60 * 60 * 24 * 7; // 7天
  let id = customShortId || (await env.SUB_STORE.get(dedupKey));
  let reusedCustomId = false;

  if (customShortId) {
    reusedCustomId = Boolean(await env.SUB_STORE.get(`sub:${customShortId}`));
    await env.SUB_STORE.put(`sub:${customShortId}`, JSON.stringify(payload), {
      expirationTtl: ttl,
    });
    await env.SUB_STORE.put(dedupKey, customShortId, {
      expirationTtl: ttl,
    });
    id = customShortId;
  } else if (!id) {
    id = await createUniqueShortId(env);

    await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload), {
      expirationTtl: ttl,
    });

    await env.SUB_STORE.put(dedupKey, id, {
      expirationTtl: ttl,
    });
  }

  const origin = url.origin;
  const accessToken = env.SUB_ACCESS_TOKEN || '';
  const withToken = (target) => {
    const subUrl = new URL(`${origin}/sub/${id}`);
    if (target) subUrl.searchParams.set('target', target);
    if (accessToken) subUrl.searchParams.set('token', accessToken);
    return subUrl.toString();
  };

  return json({
    ok: true,
    storage: 'kv',
    deduplicated: true,
    shortId: id,
    customShortId: Boolean(customShortId),
    urls: {
      auto: withToken(''),
      raw: withToken('raw'),
      clash: withToken('clash'),
      surge: withToken('surge'),
    },
    counts: {
      inputNodes: baseNodes.length + appendNodes.length,
      preferredEndpoints: preferredEndpoints.length,
      outputNodes: nodes.length,
    },
    preview: coreSummarizeNodes(nodes, 20),
    warnings: [
      ...(baseParsed.warnings || []),
      ...(appendParsed.warnings || []),
      ...(preferredParsed.warnings || []),
      ...(expanded.warnings || []),
      ...(accessToken ? [] : ['未检测到 SUB_ACCESS_TOKEN，订阅链接将没有第二层访问保护。']),
      ...(reusedCustomId ? [`固定订阅标识 ${id} 已存在，已用最新节点内容覆盖更新。`] : []),
    ],
  });
}

function validateAccessToken(url, env) {
  const expected = env.SUB_ACCESS_TOKEN;
  if (!expected) return { ok: true };
  const provided = url.searchParams.get('token') || '';
  if (!provided || provided !== expected) {
    return { ok: false, response: text('Forbidden: invalid token', 403) };
  }
  return { ok: true };
}

async function handleSub(url, env) {
  const tokenCheck = validateAccessToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  const id = url.pathname.split('/').pop();
  if (!id) return text('missing id', 400);

  const raw = await env.SUB_STORE.get(`sub:${id}`);
  if (!raw) return text('not found', 404);

  const record = JSON.parse(raw);
  const nodes = (record.nodes || []).map(normalizeStoredNode);
  const target = (url.searchParams.get('target') || 'raw').toLowerCase();

  if (target === 'clash') {
    return text(renderClash(nodes), 200, 'text/yaml; charset=utf-8');
  }
  if (target === 'surge') {
    return text(
      renderSurge(nodes, url.origin + url.pathname, env.SUB_ACCESS_TOKEN || ''),
      200,
      'text/plain; charset=utf-8',
    );
  }
  return text(renderRaw(nodes), 200, 'text/plain; charset=utf-8');
}

export { buildNodes, ensureUniqueNodeNames, parseRawLinks, renderRaw, renderClash };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type',
        },
      });
    }

    if (request.method === 'POST' && url.pathname === '/api/generate') {
      return handleGenerate(request, env, url);
    }

    if (request.method === 'GET' && url.pathname.startsWith('/sub/')) {
      return handleSub(url, env);
    }

    return env.ASSETS.fetch(request);
  },
};
