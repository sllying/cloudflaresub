import assert from 'node:assert/strict';
import {
  buildNodes as buildWorkerNodes,
  ensureUniqueNodeNames,
  parseRawLinks as parseWorkerRawLinks,
  renderRaw as renderWorkerRaw,
  renderClash as renderWorkerClash,
} from '../src/worker.js';
import {
  decryptPayload,
  encryptPayload,
  expandNodes,
  parseNodeLinks,
  parsePreferredEndpoints,
  renderClashSubscription,
  renderRawSubscription,
  renderSurgeSubscription,
} from '../src/core.js';

const vmess = 'vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJkZW1vLXdzLXRscyIsCiAgImFkZCI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAicG9ydCI6ICI0NDMiLAogICJpZCI6ICIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLAogICJzY3kiOiAiYXV0byIsCiAgIm5ldCI6ICJ3cyIsCiAgInRscyI6ICJ0bHMiLAogICJwYXRoIjogIi93cyIsCiAgImhvc3QiOiAiZWRnZS5leGFtcGxlLmNvbSIsCiAgInNuaSI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAiZnAiOiAiY2hyb21lIiwKICAiYWxwbiI6ICJoMixodHRwLzEuMSIKfQ==';

const { nodes } = parseNodeLinks(vmess);
assert.equal(nodes.length, 1);
assert.equal(nodes[0].type, 'vmess');
assert.equal(nodes[0].server, 'edge.example.com');

const { endpoints } = parsePreferredEndpoints('104.16.1.2#HK\n104.17.2.3:2053#US');
assert.equal(endpoints.length, 2);
assert.equal(parseNodeLinks('').nodes.length, 0);
assert.equal(parsePreferredEndpoints('').endpoints.length, 0);

const expanded = expandNodes(nodes, endpoints, { keepOriginalHost: true, namePrefix: 'CF' });
assert.equal(expanded.nodes.length, 2);
assert.equal(expanded.nodes[0].server, '104.16.1.2');
assert.equal(expanded.nodes[0].hostHeader, 'edge.example.com');
assert.equal(expanded.nodes[1].port, 2053);

const withoutPreferred = expandNodes(nodes, [], { keepOriginalHost: true, namePrefix: 'CF' });
assert.equal(withoutPreferred.nodes.length, 1);
assert.equal(withoutPreferred.nodes[0].server, 'edge.example.com');

const raw = renderRawSubscription(expanded.nodes);
assert.ok(raw.length > 10);

const clash = renderClashSubscription(expanded.nodes);
assert.match(clash, /proxies:/);
assert.match(clash, /edge\.example\.com/);

const workerNodes = ensureUniqueNodeNames(buildWorkerNodes(
  [
    { ...nodes[0], name: '德国-DNS加速-x | 通用' },
    { ...nodes[0], name: '德国-DNS加速-x | 通用' },
  ],
  [{ server: '104.16.1.2', remark: '通用' }],
  { keepOriginalHost: true, namePrefix: '' },
));
assert.equal(workerNodes[0].name, '德国-DNS加速-x | 通用 | 通用');
assert.equal(workerNodes[1].name, '德国-DNS加速-x | 通用 | 通用 | 2');

const appendedNode = { ...nodes[0], name: '直连保留节点', server: 'keep.example.com' };
const combinedNodes = buildWorkerNodes(nodes, endpoints, {
  keepOriginalHost: true,
  namePrefix: 'CF',
});
const mergedNodes = ensureUniqueNodeNames(
  combinedNodes.concat([appendedNode]),
);
assert.equal(buildWorkerNodes(nodes, [{ server: '104.16.1.2', remark: 'HK' }], {
  keepOriginalHost: true,
  namePrefix: 'CF',
})[0].server, '104.16.1.2');
assert.equal(mergedNodes.at(-1).server, 'keep.example.com');
assert.equal(mergedNodes.at(-1).name, '直连保留节点');

const realityUri =
  'vless://6a17fcfe-8181-43b9-b54f-456d66b6aa95@136.244.108.214:47410?encryption=none&type=tcp&security=reality&sni=www.apple.com&fp=chrome&pbk=xnVX0R1BFquUHbFxmIa2oAwDfix-e2z_Omjb4_JAv2k&sid=01f1c4547e5c1823&spx=%2F#Reality-Test';
const realityNodes = parseWorkerRawLinks(realityUri);
assert.equal(realityNodes.length, 1);
assert.equal(realityNodes[0].security, 'reality');
assert.equal(realityNodes[0].params.pbk, 'xnVX0R1BFquUHbFxmIa2oAwDfix-e2z_Omjb4_JAv2k');
assert.equal(realityNodes[0].params.sid, '01f1c4547e5c1823');
const realityRendered = Buffer.from(renderWorkerRaw(realityNodes), 'base64').toString('utf8');
assert.match(realityRendered, /security=reality/);
assert.match(realityRendered, /pbk=xnVX0R1BFquUHbFxmIa2oAwDfix-e2z_Omjb4_JAv2k/);
assert.match(realityRendered, /sid=01f1c4547e5c1823/);
assert.match(realityRendered, /spx=%2F/);
const realityClash = renderWorkerClash(realityNodes);
assert.match(realityClash, /client-fingerprint: "chrome"/);
assert.match(realityClash, /reality-opts:/);
assert.match(realityClash, /public-key: "xnVX0R1BFquUHbFxmIa2oAwDfix-e2z_Omjb4_JAv2k"/);
assert.match(realityClash, /short-id: "01f1c4547e5c1823"/);

const legacyRealityNode = {
  type: 'vless',
  name: 'Legacy-Reality',
  server: '64.176.224.114',
  port: 443,
  uuid: '33f3d64f-6dd8-47dc-b90d-801ec94d2b36',
  network: 'tcp',
  tls: true,
  security: 'reality',
  sni: 'www.constant.com',
  fp: 'chrome',
  params: {
    type: 'tcp',
    security: 'reality',
    sni: 'www.constant.com',
    fp: 'chrome',
    pbk: 'sHgjFeswmKfYKy57P3MrlbxEriSt7BEkzGblKwtGxFE',
    sid: '63f61ce9',
    spx: '/',
    encryption: 'none',
  },
};
const legacyRealityRaw = Buffer.from(renderWorkerRaw([legacyRealityNode]), 'base64').toString('utf8');
assert.match(legacyRealityRaw, /security=reality/);
assert.match(legacyRealityRaw, /pbk=sHgjFeswmKfYKy57P3MrlbxEriSt7BEkzGblKwtGxFE/);
assert.match(legacyRealityRaw, /sid=63f61ce9/);
const legacyRealityClash = renderWorkerClash([legacyRealityNode]);
assert.match(legacyRealityClash, /servername: "www.constant.com"/);
assert.match(legacyRealityClash, /client-fingerprint: "chrome"/);
assert.match(legacyRealityClash, /public-key: "sHgjFeswmKfYKy57P3MrlbxEriSt7BEkzGblKwtGxFE"/);

const trojanWsUri =
  'trojan://password123@example.com:443?type=ws&security=tls&host=cdn.example.com&sni=cdn.example.com&path=%2Fws#Trojan-WS';
const trojanWsNodes = parseWorkerRawLinks(trojanWsUri);
const trojanWsRaw = Buffer.from(renderWorkerRaw(trojanWsNodes), 'base64').toString('utf8');
assert.match(trojanWsRaw, /type=ws/);
assert.match(trojanWsRaw, /host=cdn.example.com/);
assert.match(trojanWsRaw, /path=%2Fws/);
const trojanWsClash = renderWorkerClash(trojanWsNodes);
assert.match(trojanWsClash, /type: trojan/);
assert.match(trojanWsClash, /network: ws/);
assert.match(trojanWsClash, /Host: "cdn\.example\.com"/);

const surge = renderSurgeSubscription(expanded.nodes, 'https://sub.example.com/sub/demo?target=surge');
assert.match(surge, /\[Proxy]/);
assert.match(surge, /vmess/);

const secret = 'this-is-a-very-secret-key';
const token = await encryptPayload({ nodes: expanded.nodes }, secret);
const payload = await decryptPayload(token, secret);
assert.equal(payload.nodes.length, 2);

console.log('smoke test passed');
