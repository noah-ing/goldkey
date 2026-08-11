import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { access, lstat } from "node:fs/promises";
import { ReadBuffer, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import { InvalidInputError, LocalStateError } from "../errors.mjs";

const GRACEFUL_CLOSE_MS = 2_000;
const MAX_STDERR_DIAGNOSTICS = 16;
const MAX_STDERR_DIAGNOSTIC_BYTES = 4096;

function writeStderrDiagnostic(stream, count, chunk) {
  if (count > MAX_STDERR_DIAGNOSTICS) return;
  const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  const sample = bytes.subarray(0, MAX_STDERR_DIAGNOSTIC_BYTES);
  const hash = createHash("sha256").update(sample).digest("hex");
  stream.write(
    `[goldkey-mcp] upstream stderr: count=${count} sha256=${hash} sampled_bytes=${sample.byteLength} truncated=${bytes.byteLength > sample.byteLength}\n`,
  );
}

async function assertExecutable(filename) {
  let metadata;
  try {
    metadata = await lstat(filename);
    await access(filename, fsConstants.X_OK);
  } catch (cause) {
    throw new LocalStateError(`Configured MCP upstream command is not executable: ${filename}`, { cause });
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new LocalStateError("Configured MCP upstream command must be a regular executable, not a symlink");
  }
  if (process.platform !== "win32") {
    if ((metadata.mode & 0o022) !== 0) {
      throw new LocalStateError("Configured MCP upstream command must not be writable by group or other users");
    }
    const effectiveUid = process.geteuid?.();
    if (effectiveUid !== undefined && metadata.uid !== 0 && metadata.uid !== effectiveUid) {
      throw new LocalStateError("Configured MCP upstream command must be owned by root or the launcher user");
    }
  }
}

async function assertWorkingDirectory(directory) {
  let metadata;
  try {
    metadata = await lstat(directory);
  } catch (cause) {
    throw new LocalStateError(`Unable to inspect configured MCP upstream cwd: ${directory}`, { cause });
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new LocalStateError("Configured MCP upstream cwd must be a directory, not a symlink");
  }
  if (process.platform !== "win32" && (metadata.mode & 0o022) !== 0) {
    throw new LocalStateError("Configured MCP upstream cwd must not be writable by group or other users");
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    timer.unref?.();
  });
}

/**
 * An MCP SDK Transport that deliberately does not inherit the launcher's
 * ambient environment. The official StdioClientTransport adds HOME/PATH/etc.;
 * this strict transport passes only the operator's resolved allowlist.
 */
export class StrictStdioClientTransport {
  #parameters;
  #readBuffer;
  #process;
  #started = false;
  #closed = false;
  #closeEmitted = false;
  #stderr;

  constructor({ command, args, cwd, env, maxMessageBytes, stderr = process.stderr }) {
    if (typeof command !== "string" || !Array.isArray(args) || typeof cwd !== "string") {
      throw new InvalidInputError("Strict MCP stdio transport requires fixed command, args, and cwd");
    }
    if (!env || typeof env !== "object" || Array.isArray(env)) {
      throw new InvalidInputError("Strict MCP stdio transport requires one explicit environment allowlist");
    }
    if (!Number.isSafeInteger(maxMessageBytes) || maxMessageBytes < 64 * 1024 || maxMessageBytes > 10 * 1024 * 1024) {
      throw new InvalidInputError("Strict MCP stdio maxMessageBytes is outside the safe range");
    }
    if (!stderr || typeof stderr.write !== "function") {
      throw new InvalidInputError("Strict MCP stdio stderr must be a writable stream");
    }
    this.#parameters = Object.freeze({
      command,
      args: Object.freeze([...args]),
      cwd,
      env: Object.freeze({ ...env }),
      maxMessageBytes,
    });
    this.#readBuffer = new ReadBuffer({ maxBufferSize: maxMessageBytes });
    this.#stderr = stderr;
  }

  get pid() {
    return this.#process?.pid ?? null;
  }

  async start() {
    if (this.#started) throw new Error("StrictStdioClientTransport has already been started");
    if (this.#closed) throw new Error("StrictStdioClientTransport is closed");
    this.#started = true;
    await Promise.all([
      assertExecutable(this.#parameters.command),
      assertWorkingDirectory(this.#parameters.cwd),
    ]);

    await new Promise((resolve, reject) => {
      let settled = false;
      let child;
      try {
        child = spawn(this.#parameters.command, this.#parameters.args, {
          cwd: this.#parameters.cwd,
          env: { ...this.#parameters.env },
          shell: false,
          windowsHide: true,
          stdio: ["pipe", "pipe", "pipe"],
        });
      } catch (cause) {
        reject(cause);
        return;
      }
      this.#process = child;
      child.once("spawn", () => {
        settled = true;
        resolve();
      });
      child.once("error", (error) => {
        if (!settled) reject(error);
        this.onerror?.(error);
      });
      child.once("close", (code, signal) => {
        this.#process = undefined;
        this.#readBuffer.clear();
        if (!this.#closed && code !== 0) {
          this.onerror?.(new Error(`MCP upstream exited unexpectedly (${signal ?? code ?? "unknown"})`));
        }
        this.#emitClose();
      });
      child.stdin.on("error", (error) => this.onerror?.(error));
      child.stdout.on("error", (error) => this.onerror?.(error));
      child.stdout.on("data", (chunk) => {
        try {
          this.#readBuffer.append(chunk);
          for (;;) {
            const message = this.#readBuffer.readMessage();
            if (message === null) break;
            this.onmessage?.(message);
          }
        } catch (error) {
          this.onerror?.(error);
          this.close().catch((closeError) => this.onerror?.(closeError));
        }
      });
      child.stderr.on("error", (error) => this.onerror?.(error));
      // Drain stderr without ever exposing upstream-controlled bytes to the
      // agent or operator. A short, content-free diagnostic is enough to
      // correlate a failure with an upstream log without turning stderr into
      // an exfiltration channel.
      let stderrCount = 0;
      child.stderr.on("data", (chunk) => {
        stderrCount += 1;
        writeStderrDiagnostic(this.#stderr, stderrCount, chunk);
      });
    });
  }

  async send(message) {
    const input = this.#process?.stdin;
    if (!input || this.#closed) throw new Error("MCP upstream transport is not connected");
    const serialized = serializeMessage(message);
    if (Buffer.byteLength(serialized, "utf8") > this.#parameters.maxMessageBytes) {
      throw new Error(`MCP upstream message exceeds ${this.#parameters.maxMessageBytes} bytes`);
    }
    await new Promise((resolve, reject) => {
      input.write(serialized, (error) => error ? reject(error) : resolve());
    });
  }

  async close() {
    if (this.#closed) return;
    this.#closed = true;
    const child = this.#process;
    this.#process = undefined;
    this.#readBuffer.clear();
    if (!child) {
      this.#emitClose();
      return;
    }
    const exited = new Promise((resolve) => child.once("close", resolve));
    try {
      child.stdin?.end();
    } catch {
      // Continue to bounded termination below.
    }
    await Promise.race([exited, delay(GRACEFUL_CLOSE_MS)]);
    if (child.exitCode === null && child.signalCode === null) {
      try {
        child.kill("SIGTERM");
      } catch {
        // Continue to the final bounded check.
      }
      await Promise.race([exited, delay(GRACEFUL_CLOSE_MS)]);
    }
    if (child.exitCode === null && child.signalCode === null) {
      try {
        child.kill("SIGKILL");
      } catch {
        // The process may have exited between the check and kill.
      }
    }
    this.#emitClose();
  }

  #emitClose() {
    if (this.#closeEmitted) return;
    this.#closeEmitted = true;
    this.onclose?.();
  }
}

Object.freeze(StrictStdioClientTransport.prototype);
