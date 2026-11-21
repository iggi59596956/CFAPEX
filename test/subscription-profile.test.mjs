import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdtempSync, readFileSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join} from "node:path";
import {pathToFileURL} from "node:url";
import test from "node:test";

const root = dirname(new URL("../CFAPEX-worker.1.5.js", import.meta.url).pathname);
const workerPath = join(root, "CFAPEX-worker.1.5.js");
const zipPath = join(root, "CFAPEX-Pages-1.5.zip");
const TITLE = "88888无限私人节点";
const URLTEST = "自动选择";
const PASSWORD = "test-password-88888";
const HOST = "trial.example";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function python(code, input) {
  const result = spawnSync("python3", ["-c", code], {input, encoding: "utf8", maxBuffer: 20_000_000});
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || "python failed");
  return result.stdout;
}

function parseYaml(text) {
  return JSON.parse(python(
    "import json,sys,yaml\nprint(json.dumps(yaml.safe_load(sys.stdin.read()), ensure_ascii=False))",
    text
  ));
}

async function subscriptionToken(password) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    {name: "HMAC", hash: "SHA-256"},
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("CFAPEX subscription v1"));
  return [...new Uint8Array(signature)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function decodeFilenameStar(header) {
  const match = header.match(/filename\*=UTF-8''([^;]+)/);
  assert.ok(match, header);
  const bytes = [];
  const value = match[1];
  for (let i = 0; i < value.length; i++) {
    if (value[i] === "%") {
      bytes.push(Number.parseInt(value.slice(i + 1, i + 3), 16));
      i += 2;
    } else bytes.push(value.charCodeAt(i));
  }
  return new TextDecoder().decode(Uint8Array.from(bytes));
}

function assertProfileHeaders(headers) {
  const disposition = headers.get("content-disposition");
  const title = headers.get("profile-title");
  assert.equal(headers.get("content-type"), "text/yaml;charset=utf-8");
  assert.equal(disposition, 'attachment; filename="88888.yaml"; filename*=UTF-8\'\'88888%E6%97%A0%E9%99%90%E7%A7%81%E4%BA%BA%E8%8A%82%E7%82%B9.yaml');
  assert.equal(title, "base64:ODg4ODjml6DpmZDnp4HkurroioLngrk=");
  for (const value of [disposition, title]) {
    assert.match(value, /^[\t\x20-\x7e]+$/);
  }
  assert.equal(decodeFilenameStar(disposition), TITLE + ".yaml");
  assert.equal(Buffer.from(title.slice("base64:".length), "base64").toString("utf8"), TITLE);
}

function assertYamlProfile(text) {
  const doc = parseYaml(text);
  const proxies = doc.proxies;
  const groups = doc["proxy-groups"];
  assert.ok(Array.isArray(proxies) && proxies.length > 0);
  assert.equal(groups.length, 2);
  const select = groups.find(group => group.type === "select");
  const urltest = groups.find(group => group.type === "url-test");
  assert.equal(select.name, TITLE);
  assert.equal(urltest.name, URLTEST);
  assert.equal(groups.some(group => group.name === "节点选择"), false);
  assert.equal(select.proxies[0], URLTEST);
  const nodeNames = proxies.map(proxy => proxy.name);
  assert.equal(new Set(nodeNames).size, nodeNames.length);
  assert.deepEqual(select.proxies.slice(1), nodeNames);
  assert.ok(urltest.proxies.length > 0);
  assert.ok(urltest.proxies.every(name => nodeNames.includes(name)));
  for (const name of [...select.proxies, ...urltest.proxies]) {
    if (name !== URLTEST) assert.ok(nodeNames.includes(name), name);
  }
  assert.equal(nodeNames.includes(TITLE), false);
  assert.equal(nodeNames.includes(URLTEST), false);
  assert.equal(doc.rules.at(-1), "MATCH," + TITLE);
  assert.equal(doc.rules.includes("MATCH,节点选择"), false);
  assert.equal(doc.rules.includes("DOMAIN-SUFFIX,cn,DIRECT"), true);
  assert.equal(doc.rules.includes("GEOIP,CN,DIRECT"), true);
  assert.equal(text.includes("节点选择"), false);
  for (const proxy of proxies) {
    assert.equal(proxy.type, "vless");
    assert.equal(proxy.network, "ws");
    assert.equal(proxy.servername, HOST);
    assert.equal(proxy.udp, false);
    assert.equal(proxy["ws-opts"].headers.Host, HOST);
  }
  return doc;
}

let worker;
let token;
let fetches = 0;

test("zip member is the worker bytes", () => {
  const workerBytes = readFileSync(workerPath);
  const hex = python(
    "import sys,zipfile\n"
    + "from pathlib import Path\n"
    + "z=zipfile.ZipFile(r'''" + zipPath + "''')\n"
    + "data=z.read('_worker.js')\n"
    + "assert z.namelist()==['_worker.js']\n"
    + "print(data.hex())\n",
    ""
  ).trim();
  const zipped = Buffer.from(hex, "hex");
  assert.equal(Buffer.compare(zipped, workerBytes), 0);
  assert.equal(sha256(workerBytes), sha256(zipped));
  const source = workerBytes.toString("utf8");
  assert.equal(source.includes("6IqC54K56YCJ5oup"), false);
  assert.equal(source.split("ODg4ODjml6DpmZDnp4HkurroioLngrk=").length - 1, 1);
});

test("clash subscription YAML, headers, and sing-box references", async () => {
  fetches = 0;
  globalThis.fetch = () => {
    fetches += 1;
    throw new Error("network disabled");
  };
  globalThis.caches = {default: {async match() {return null;}, async put() {}, async delete() {return false;}}};
  const dir = mkdtempSync(join(tmpdir(), "cfapex-profile-"));
  writeFileSync(join(dir, "sockets.mjs"), "export function connect(){throw new Error('socket disabled')}\n");
  const source = readFileSync(workerPath, "utf8").replace(
    'from"cloudflare:sockets"',
    `from"${pathToFileURL(join(dir, "sockets.mjs")).href}"`
  );
  const modulePath = join(dir, "worker.mjs");
  writeFileSync(modulePath, source);
  worker = await import(pathToFileURL(modulePath).href);
  token = await subscriptionToken(PASSWORD);
  const env = {A: PASSWORD, XHTTP: "0", TROJAN: "0"};
  const ctx = {waitUntil() {}};

  async function get(path, headers = {}) {
    const url = "https://" + HOST + path;
    const lower = new Map(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
    lower.set("host", HOST);
    const request = {
      url,
      method: "GET",
      headers: {
        get(name) {return lower.get(String(name).toLowerCase()) ?? null;},
        has(name) {return lower.has(String(name).toLowerCase());}
      }
    };
    const response = await worker.default.fetch(request, env, ctx);
    return {response, body: await response.text()};
  }

  const cases = [
    `/s/${token}?format=clash&protocol=vless&limit=4`,
    `/s/${token}?format=yaml&protocol=vless&limit=4`,
    `/s/${token}/clash?protocol=vless&limit=4`
  ];
  for (const path of cases) {
    const {response, body} = await get(path);
    assert.equal(response.status, 200, path);
    assertProfileHeaders(response.headers);
    const doc = assertYamlProfile(body);
    assert.equal(doc.proxies.length, 4);
  }

  const ua = await get(`/s/${token}?protocol=vless&limit=4`, {"User-Agent": "mihomo/1.18"});
  assert.equal(ua.response.status, 200);
  assertProfileHeaders(ua.response.headers);
  assertYamlProfile(ua.body);

  const plain = await get(`/s/${token}?protocol=vless&limit=2`, {"User-Agent": "curl/8.0"});
  assert.equal(plain.response.status, 200);
  assert.equal(plain.response.headers.get("profile-title"), null);
  assert.equal(plain.response.headers.get("content-disposition"), null);
  assert.match(plain.body, /^vless:\/\//);
  assert.equal(plain.body.includes("节点选择"), false);

  const sing = await get(`/s/${token}?format=singbox&protocol=vless&limit=4`);
  assert.equal(sing.response.status, 200);
  assert.equal(sing.response.headers.get("profile-title"), null);
  const json = JSON.parse(sing.body);
  const selector = json.outbounds.filter(item => item.type === "selector");
  const urltest = json.outbounds.filter(item => item.type === "urltest");
  assert.equal(selector.length, 1);
  assert.equal(selector[0].tag, TITLE);
  assert.equal(urltest.length, 1);
  assert.equal(urltest[0].tag, URLTEST);
  assert.equal(json.route.final, TITLE);
  assert.equal(sing.body.includes("节点选择"), false);
  assert.equal(fetches, 0);
});
