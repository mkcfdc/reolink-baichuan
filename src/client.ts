import {
  AES_IV,
  Command,
  EncFlag,
  headerLength,
  MessageClass,
  PtzCommand,
  StreamByte,
  StreamType,
  type PtzCommandName,
  type StreamName,
} from "./commands.ts";
import { aes128CfbDecrypt, aes128CfbEncrypt, baichuanAesKey, credentialHash } from "./crypto.ts";
import { decodeFrame, drainFrames, encodeFrame, type Frame } from "./frame.ts";
import { demuxMedia, type MediaPacket } from "./media.ts";
import { bcXor, extensionXml, extractTag, loginXml, logoutXml, previewXml, ptzXml, xmlDocument } from "./xml.ts";

export type Encryption = "auto" | "none" | "bc" | "aes";
export type LoginStyle = "auto" | "legacy" | "nonce";

export interface BaichuanOptions {
  host: string;
  port?: number;
  username?: string;
  password?: string;
  /** Default NVR channel. Direct cameras use 0. */
  channel?: number;
  /** none, Baichuan XOR, AES-128-CFB, or negotiate. */
  encryption?: Encryption;
  /**
   * legacy: 64-byte MD5 user/password body.
   * nonce: empty login to fetch a nonce, then modern XML login.
   * auto: nonce first, then legacy.
   */
  loginStyle?: LoginStyle;
  /** Clip MD5 hex to 31 (camera compare) or send all 32. */
  credentialClip?: 31 | 32;
  /** Insert a dash between nonce and password when deriving the AES key. */
  aesKeyDash?: boolean;
  timeoutMs?: number;
  keepaliveMs?: number;
  debug?: boolean;
}

export interface RequestOptions {
  channel?: number;
  streamId?: number;
  handle?: number;
  messageClass?: number;
  encryption?: Encryption | "session";
  payloadOffset?: number;
  timeoutMs?: number;
  /** Expect no reply (talk audio). */
  noReply?: boolean;
}

export interface PreviewOptions {
  channel?: number;
  stream?: keyof typeof StreamType | StreamName;
  handle?: number;
  /** Some stop commands use the reversed magic. */
  stopMagic?: "normal" | "reversed";
}

export interface TalkOptions {
  channel?: number;
  duplex?: "FDX" | "HDX";
  audioType?: "adpcm" | "aac";
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class BaichuanClient {
  readonly options: Required<Pick<BaichuanOptions, "host" | "port" | "channel" | "encryption" | "loginStyle" | "credentialClip" | "aesKeyDash" | "timeoutMs" | "keepaliveMs" | "debug">> & BaichuanOptions;
  username: string;
  password: string;
  sessionEncryption: "none" | "bc" | "aes" = "bc";
  nonce?: string;
  aesKey?: Uint8Array;
  deviceInfoXml?: string;
  private conn?: Deno.Conn;
  private buffer: Uint8Array = new Uint8Array(0);
  private handle = 1;
  private queue: Frame[] = [];
  private waiters: Array<(frame: Frame) => void> = [];
  private pump?: Promise<void>;
  private closed = false;
  private keepalive?: ReturnType<typeof setInterval>;

  constructor(opts: BaichuanOptions) {
    this.username = opts.username ?? "admin";
    this.password = opts.password ?? "";
    this.options = {
      port: 9000,
      channel: 0,
      encryption: "auto",
      loginStyle: "auto",
      credentialClip: 31,
      aesKeyDash: true,
      timeoutMs: 8000,
      keepaliveMs: 0,
      debug: false,
      ...opts,
    };
  }

  async connect(): Promise<void> {
    if (this.conn) return;
    this.conn = await Deno.connect({
      hostname: this.options.host,
      port: this.options.port,
    });
    this.closed = false;
    this.pump = this.readLoop();
  }

  async login(): Promise<string> {
    await this.connect();
    const styles: LoginStyle[] = this.options.loginStyle === "auto"
      ? ["nonce", "legacy"]
      : [this.options.loginStyle];
    let lastError: unknown;
    for (const style of styles) {
      try {
        return await this.loginOnce(style);
      } catch (err) {
        lastError = err;
        this.debug("login style failed", style, err);
      }
    }
    throw lastError instanceof Error ? lastError : new Error("login failed");
  }

  private async loginOnce(style: LoginStyle): Promise<string> {
    const enc = this.options.encryption === "none"
      ? EncFlag.none
      : this.options.encryption === "aes"
      ? EncFlag.aes
      : this.options.encryption === "bc"
      ? EncFlag.bc
      : EncFlag.aes;
    const legacyBody = style === "legacy" ? this.legacyCredentialBody() : new Uint8Array();
    await this.send({
      id: Command.login,
      body: legacyBody,
      messageClass: MessageClass.legacyRequest,
      code: enc,
      encryption: "none",
    });
    const nonceMsg = await this.waitFor(Command.login, this.options.timeoutMs);
    const nonceXml = decoder.decode(this.decrypt(nonceMsg));
    this.nonce = extractTag(nonceXml, "nonce");
    const ack = nonceMsg.code;
    if (ack === EncFlag.aesAck || this.options.encryption === "aes") {
      this.sessionEncryption = "aes";
    } else if (ack === EncFlag.bcAck || this.options.encryption === "bc" || nonceXml.includes("<nonce>")) {
      this.sessionEncryption = "bc";
    } else if (this.options.encryption === "none") {
      this.sessionEncryption = "none";
    }
    if (this.nonce && this.sessionEncryption === "aes") {
      this.aesKey = baichuanAesKey(this.nonce, this.password, this.options.aesKeyDash);
    }
    if (!this.nonce && nonceXml.includes("<DeviceInfo")) {
      this.deviceInfoXml = nonceXml;
      this.startKeepalive();
      return nonceXml;
    }
    if (!this.nonce) throw new Error(`no nonce in login reply: ${nonceXml.slice(0, 180)}`);
    const user = credentialHash(this.username + this.nonce, this.options.credentialClip);
    const pass = credentialHash(this.password + this.nonce, this.options.credentialClip);
    const body = encoder.encode(loginXml(user, pass));
    await this.send({
      id: Command.login,
      body,
      messageClass: MessageClass.modernRequest,
      code: 0,
      encryption: "bc",
    });
    const reply = await this.waitFor(Command.login, this.options.timeoutMs);
    if (reply.code !== 0 && reply.code !== 200) {
      throw new Error(`login rejected, status ${reply.code}`);
    }
    this.deviceInfoXml = decoder.decode(this.decrypt(reply));
    this.startKeepalive();
    return this.deviceInfoXml;
  }

  legacyCredentialBody(): Uint8Array {
    const body = new Uint8Array(64);
    const user = encoder.encode(credentialHash(this.username, this.options.credentialClip));
    const pass = encoder.encode(credentialHash(this.password, this.options.credentialClip));
    body.set(user.subarray(0, 31), 0);
    body.set(pass.subarray(0, 31), 32);
    return body;
  }

  async request(id: number, xml?: string, opts: RequestOptions = {}): Promise<Frame> {
    const body = xml ? encoder.encode(xmlDocument(xml)) : new Uint8Array();
    await this.send({
      id,
      body,
      messageClass: opts.messageClass ?? MessageClass.modernRequest,
      channelId: opts.channel ?? this.options.channel,
      streamId: opts.streamId ?? 0,
      handle: opts.handle,
      payloadOffset: opts.payloadOffset,
      encryption: opts.encryption ?? "session",
    });
    if (opts.noReply) {
      return { magic: 0, id, channelId: 0, streamId: 0, handle: 0, code: 0, messageClass: 0, payloadOffset: 0, body: new Uint8Array() };
    }
    return await this.waitFor(id, opts.timeoutMs ?? this.options.timeoutMs);
  }

  async requestXml(id: number, xml?: string, opts: RequestOptions = {}): Promise<string> {
    const frame = await this.request(id, xml, opts);
    return decoder.decode(this.decrypt(frame));
  }

  getVersion(): Promise<string> {
    return this.requestXml(Command.versionInfo);
  }

  getSupport(): Promise<string> {
    return this.requestXml(Command.support);
  }

  getAbility(token = "system"): Promise<string> {
    return this.requestXml(Command.abilityInfo, `<AbilityInfo version="1.1"><token>${token}</token></AbilityInfo>`);
  }

  getAbilitySupport(): Promise<string> {
    return this.requestXml(Command.abilitySupport);
  }

  getSystemGeneral(): Promise<string> {
    return this.requestXml(Command.systemGeneral);
  }

  getNetwork(): Promise<string> {
    return this.requestXml(Command.ip);
  }

  getPorts(): Promise<string> {
    return this.requestXml(Command.serverPort);
  }

  getWifiSignal(): Promise<string> {
    return this.requestXml(Command.wifiSignal);
  }

  getStreamInfo(): Promise<string> {
    return this.requestXml(Command.streamInfoList);
  }

  getVideoInput(channel = this.options.channel): Promise<string> {
    return this.requestXml(Command.videoInput, `<VideoInput version="1.1"><channelId>${channel}</channelId></VideoInput>`);
  }

  getOsd(channel = this.options.channel): Promise<string> {
    return this.requestXml(Command.osdChannelName, `<OsdChannelName version="1.1"><channelId>${channel}</channelId></OsdChannelName>`);
  }

  getRecordCfg(): Promise<string> {
    return this.requestXml(Command.recordCfg);
  }

  getCompression(): Promise<string> {
    return this.requestXml(Command.compression);
  }

  getStorage(): Promise<string> {
    return this.requestXml(Command.hddInfoList);
  }

  getLed(): Promise<string> {
    return this.requestXml(Command.ledState);
  }

  setLed(state: "auto" | "open" | "close", channel = this.options.channel): Promise<string> {
    return this.requestXml(Command.ledStateWrite, `<LedState version="1.1"><channelId>${channel}</channelId><state>${state}</state></LedState>`);
  }

  getFloodlight(): Promise<string> {
    return this.requestXml(Command.floodlightStatus);
  }

  setFloodlight(durationSec: number, channel = this.options.channel): Promise<string> {
    return this.requestXml(
      Command.floodlightManual,
      `<FloodlightManual version="1.1"><channelId>${channel}</channelId><duration>${durationSec}</duration></FloodlightManual>`,
    );
  }

  getTalkAbility(channel = this.options.channel): Promise<string> {
    return this.requestXml(Command.talkAbility, extensionXml(false, channel));
  }

  async ptz(
    command: PtzCommandName | string,
    speed = 32,
    channel = this.options.channel,
    presetId?: number,
  ): Promise<string> {
    return this.requestXml(Command.ptzControl, ptzXml(channel, command, speed, presetId));
  }

  reboot(): Promise<string> {
    return this.requestXml(Command.reboot);
  }

  subscribeEvents(channel = this.options.channel): Promise<string> {
    return this.requestXml(Command.subscribeEvents, `<AlarmEventList version="1.1"><channelId>${channel}</channelId></AlarmEventList>`);
  }

  async *events(signal?: AbortSignal): AsyncGenerator<Frame> {
    while (!this.closed && !signal?.aborted) {
      const frame = await this.nextFrame(this.options.timeoutMs).catch(() => undefined);
      if (!frame) continue;
      if (frame.id === Command.alarmEventList || frame.id === Command.channelInfo || frame.id === Command.aiState) {
        yield frame;
      } else {
        this.queue.push(frame);
      }
    }
  }

  async *preview(opts: PreviewOptions = {}): AsyncGenerator<MediaPacket> {
    const stream = resolveStream(opts.stream ?? "sub");
    const channel = opts.channel ?? this.options.channel;
    const handle = opts.handle ?? this.handle++;
    await this.send({
      id: Command.preview,
      body: encoder.encode(previewXml(channel, handle, stream)),
      messageClass: MessageClass.modernRequest,
      channelId: channel,
      streamId: StreamByte[stream as keyof typeof StreamByte] ?? 0,
      handle,
      encryption: "session",
    });
    try {
      while (!this.closed) {
        const frame = await this.waitFor(Command.preview, this.options.timeoutMs);
        const body = this.decrypt(frame);
        const bin = frame.payloadOffset > 0 ? body.slice(frame.payloadOffset) : body;
        if (bin.length < 8) continue;
        for (const packet of demuxMedia(bin)) yield packet;
      }
    } finally {
      await this.stopPreview(channel, handle, stream, opts.stopMagic).catch(() => undefined);
    }
  }

  async stopPreview(
    channel: number,
    handle: number,
    stream: string,
    stopMagic: "normal" | "reversed" = "normal",
  ): Promise<void> {
    await this.send({
      id: Command.previewStop,
      body: encoder.encode(previewXml(channel, handle, stream)),
      messageClass: MessageClass.modernRequest,
      channelId: channel,
      handle,
      encryption: "session",
      magic: stopMagic === "reversed" ? 0xf0debc0a : undefined,
    });
  }

  async talk(payload: Uint8Array, opts: TalkOptions = {}): Promise<void> {
    await this.send({
      id: Command.talk,
      body: payload,
      messageClass: MessageClass.modernRequest,
      channelId: opts.channel ?? this.options.channel,
      encryption: "session",
    });
  }

  async logout(): Promise<void> {
    await this.request(Command.logout, logoutXml(this.username, this.password), { noReply: true }).catch(() => undefined);
  }

  async close(): Promise<void> {
    this.closed = true;
    if (this.keepalive) clearInterval(this.keepalive);
    try {
      await this.logout();
    } catch {
      // already gone
    }
    this.conn?.close();
    this.conn = undefined;
  }

  text(frame: Frame): string {
    return decoder.decode(this.decrypt(frame));
  }

  private startKeepalive(): void {
    if (!this.options.keepaliveMs || this.keepalive) return;
    this.keepalive = setInterval(() => {
      this.request(Command.linkType).catch(() => undefined);
    }, this.options.keepaliveMs);
  }

  private async send(opts: {
    id: number;
    body: Uint8Array;
    messageClass: number;
    channelId?: number;
    streamId?: number;
    handle?: number;
    code?: number;
    payloadOffset?: number;
    encryption: Encryption | "session" | "none";
    magic?: number;
  }): Promise<void> {
    if (!this.conn) throw new Error("not connected");
    const mode = opts.encryption === "session" ? this.sessionEncryption : opts.encryption;
    const channelId = opts.channelId ?? 0;
    const body = this.encrypt(opts.body, mode === "auto" ? "bc" : mode, channelId);
    const packet = encodeFrame({
      id: opts.id,
      body,
      messageClass: opts.messageClass,
      channelId,
      streamId: opts.streamId,
      handle: opts.handle ?? this.handle++,
      code: opts.code ?? 0,
      payloadOffset: opts.payloadOffset,
      magic: opts.magic,
    });
    this.debug("tx", opts.id, "class", opts.messageClass.toString(16), "bytes", packet.length);
    await this.conn.write(packet);
  }

  private encrypt(body: Uint8Array, mode: "none" | "bc" | "aes", offset: number): Uint8Array {
    if (mode === "none" || body.length === 0) return body;
    if (mode === "aes") {
      if (!this.aesKey) throw new Error("AES selected but no key");
      return aes128CfbEncrypt(body, this.aesKey, AES_IV);
    }
    return bcXor(body, offset);
  }

  decrypt(frame: Frame): Uint8Array {
    const xmlEnd = frame.payloadOffset > 0 ? Math.min(frame.payloadOffset, frame.body.length) : frame.body.length;
    const xml = frame.body.subarray(0, xmlEnd);
    const bin = frame.body.subarray(xmlEnd);
    let plain = xml;
    if (this.sessionEncryption === "aes" && this.aesKey && xml.length) {
      plain = aes128CfbDecrypt(xml, this.aesKey, AES_IV);
    } else if (this.sessionEncryption !== "none" && xml.length && !looksLikeXml(xml)) {
      plain = bcXor(xml, frame.channelId);
    }
    if (!bin.length) return plain;
    const out = new Uint8Array(plain.length + bin.length);
    out.set(plain);
    out.set(bin, plain.length);
    return out;
  }

  private async waitFor(id: number, timeoutMs: number): Promise<Frame> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const idx = this.queue.findIndex((f) => f.id === id);
      if (idx >= 0) return this.queue.splice(idx, 1)[0];
      const remaining = deadline - Date.now();
      const frame = await this.nextFrame(remaining);
      if (frame.id === id) return frame;
      this.queue.push(frame);
    }
    throw new Error(`timeout waiting for message ${id}`);
  }

  private nextFrame(timeoutMs: number): Promise<Frame> {
    const queued = this.queue.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== onFrame);
        reject(new Error("timeout waiting for frame"));
      }, timeoutMs);
      const onFrame = (frame: Frame) => {
        clearTimeout(timer);
        resolve(frame);
      };
      this.waiters.push(onFrame);
    });
  }

  private async readLoop(): Promise<void> {
    const conn = this.conn;
    if (!conn) return;
    const chunk = new Uint8Array(64 * 1024);
    try {
      while (!this.closed) {
        const n = await conn.read(chunk);
        if (n === null) break;
        this.buffer = concat(this.buffer, chunk.slice(0, n)) as Uint8Array;
        const { frames, consumed } = drainFrames(this.buffer);
        if (consumed) this.buffer = this.buffer.slice(consumed);
        for (const frame of frames) {
          this.debug("rx", frame.id, "status", frame.code, "body", frame.body.length);
          const waiter = this.waiters.shift();
          if (waiter) waiter(frame);
          else this.queue.push(frame);
        }
      }
    } catch (err) {
      if (!this.closed) this.debug("read loop ended", err);
    }
  }

  private debug(...args: unknown[]): void {
    if (this.options.debug) console.error("[baichuan]", ...args);
  }
}

function resolveStream(stream: keyof typeof StreamType | StreamName): string {
  return stream in StreamType ? StreamType[stream as keyof typeof StreamType] : stream;
}

function looksLikeXml(buf: Uint8Array): boolean {
  const start = decoder.decode(buf.subarray(0, Math.min(buf.length, 16))).trimStart();
  return start.startsWith("<") || start.startsWith("<?");
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

export { headerLength, PtzCommand };
