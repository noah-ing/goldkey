import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import {
  buildHttpsRequest,
  isPublicIpAddress,
  performPinnedHttpsRequest,
  resolvePublicAddresses,
} from "../src/network.mjs";
import { NetworkPolicyError, ResponseLimitError } from "../src/errors.mjs";

test("IP classifier rejects private, link-local, loopback, documentation, multicast, mapped, and special ranges", () => {
  for (const address of [
    "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.31.1.2",
    "192.0.2.1", "192.168.1.2", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1",
    "::", "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "2002:5db8:d822::1", "3fff::1",
    "::ffff:127.0.0.1", "::ffff:169.254.169.254",
  ]) assert.equal(isPublicIpAddress(address), false, address);
  for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888"]) {
    assert.equal(isPublicIpAddress(address), true, address);
  }
});

test("DNS resolution rejects an entire mixed public/private answer set", async () => {
  await assert.rejects(
    resolvePublicAddresses("api.example.net", {
      resolve4: async () => [{ address: "93.184.216.34", ttl: 30 }, { address: "127.0.0.1", ttl: 1 }],
      resolve6: async () => {
        const error = new Error("no data");
        error.code = "ENODATA";
        throw error;
      },
    }),
    NetworkPolicyError,
  );
});

function fakeHttps({ status = 200, headers = {}, chunks = [Buffer.from("ok")] } = {}) {
  let captured;
  let written = Buffer.alloc(0);
  const requestImpl = (options, callback) => {
    captured = options;
    const outgoing = new EventEmitter();
    outgoing.write = (chunk) => { written = Buffer.concat([written, Buffer.from(chunk)]); };
    outgoing.end = () => {
      queueMicrotask(() => {
        const response = new EventEmitter();
        response.statusCode = status;
        response.headers = headers;
        response.destroy = () => {};
        callback(response);
        for (const chunk of chunks) response.emit("data", chunk);
        response.emit("end");
      });
    };
    outgoing.destroy = (error) => {
      if (error) queueMicrotask(() => outgoing.emit("error", error));
    };
    return outgoing;
  };
  return { requestImpl, captured: () => captured, written: () => written };
}

test("pinned HTTPS preserves TLS hostname/SNI, uses the chosen address, and never follows or exposes redirects", async () => {
  const fake = fakeHttps({ status: 302, headers: { location: "https://127.0.0.1/secret", "set-cookie": "session=secret", "content-type": "text/plain" } });
  const result = await performPinnedHttpsRequest({
    request: {
      url: new URL("https://api.example.net/v1/write"),
      method: "POST",
      headers: { authorization: "operator-secret", "content-length": "2" },
      body: Buffer.from("{}"),
    },
    pinnedAddress: { address: "93.184.216.34", family: 4 },
    requestImpl: fake.requestImpl,
  });
  const options = fake.captured();
  assert.equal(options.hostname, "api.example.net");
  assert.equal(options.servername, "api.example.net");
  assert.equal(options.agent, false);
  await new Promise((resolve, reject) => options.lookup("api.example.net", {}, (error, address, family) => {
    if (error) reject(error);
    else {
      assert.equal(address, "93.184.216.34");
      assert.equal(family, 4);
      resolve();
    }
  }));
  assert.equal(result.status, 302);
  assert.equal(result.headers.location, undefined);
  assert.equal(result.headers["set-cookie"], undefined);
  assert.equal(result.headers["content-type"], "text/plain");
  assert.equal(fake.written().toString(), "{}");
});

test("guarded HTTPS aborts over-limit responses instead of returning a truncation", async () => {
  const fake = fakeHttps({ chunks: [Buffer.alloc(1024 * 1024), Buffer.from("x")] });
  await assert.rejects(
    performPinnedHttpsRequest({
      request: {
        url: new URL("https://api.example.net/read"),
        method: "GET",
        headers: {},
        body: Buffer.alloc(0),
      },
      pinnedAddress: { address: "93.184.216.34", family: 4 },
      requestImpl: fake.requestImpl,
    }),
    ResponseLimitError,
  );
});

test("complete guarded request size, including operator headers, is capped at 64 KiB", () => {
  const trustedHeaders = {};
  for (let index = 0; index < 9; index += 1) trustedHeaders["x-secret-" + index] = "x".repeat(8_000);
  assert.throws(() => buildHttpsRequest({
    connector: { origin: "https://api.example.net", trusted_headers: trustedHeaders },
    operation: { method: "POST", path: "/write" },
    call: { body: { ok: true } },
  }), ResponseLimitError);
});
