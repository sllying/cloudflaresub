import assert from 'node:assert/strict';
import {
  buildNodes as buildWorkerNodes,
  ensureUniqueNodeNames,
  parseRawLinks as parseWorkerRawLinks,
  renderRaw as renderWorkerRaw,
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

const expanded = expandNodes(nodes, endpoints, { keepOriginalHost: true, namePrefix: 'CF' });
assert.equal(expanded.nodes.length, 2);
assert.equal(expanded.nodes[0].server, '104.16.1.2');
assert.equal(expanded.nodes[0].hostHeader, 'edge.example.com');
assert.equal(expanded.nodes[1].port, 2053);

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

const surge = renderSurgeSubscription(expanded.nodes, 'https://sub.example.com/sub/demo?target=surge');
assert.match(surge, /\[Proxy]/);
assert.match(surge, /vmess/);

const secret = 'this-is-a-very-secret-key';
const token = await encryptPayload({ nodes: expanded.nodes }, secret);
const payload = await decryptPayload(token, secret);
assert.equal(payload.nodes.length, 2);

console.log('smoke test passed');
