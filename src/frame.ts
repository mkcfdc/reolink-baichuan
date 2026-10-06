import {
  headerLength,
  MAGIC,
  MAGIC_REVERSED,
  NVR_MAGIC,
} from "./commands.ts";

export interface Frame {
  magic: number;
  id: number;
  channelId: number;
  streamId: number;
  handle: number;
  /** Legacy encryption-negotiation field, or modern HTTP-style status. */
  code: number;
  messageClass: number;
  payloadOffset: number;
  body: Uint8Array;
}

export interface EncodeOptions {
  id: number;
  body?: Uint8Array;
  channelId?: number;
  streamId?: number;
  handle?: number;
  code?: number;
  messageClass: number;
  payloadOffset?: number;
  magic?: number;
}

export function encodeFrame(opts: EncodeOptions): Uint8Array {
  const body = opts.body ?? new Uint8Array();
  const hlen = headerLength(opts.messageClass);
  const out = new Uint8Array(hlen + body.length);
  const v = new DataView(out.buffer);
  v.setUint32(0, opts.magic ?? MAGIC, true);
  v.setUint32(4, opts.id, true);
  v.setUint32(8, body.length, true);
  out[12] = opts.channelId ?? 0;
  out[13] = opts.streamId ?? 0;
  v.setUint16(14, opts.handle ?? 0, true);
  v.setUint16(16, opts.code ?? 0, true);
  v.setUint16(18, opts.messageClass, true);
  if (hlen === 24) v.setUint32(20, opts.payloadOffset ?? 0, true);
  out.set(body, hlen);
  return out;
}

export function decodeFrame(buf: Uint8Array, offset = 0): Frame | undefined {
  if (buf.length - offset < 20) return undefined;
  const v = new DataView(buf.buffer, buf.byteOffset + offset, buf.byteLength - offset);
  const magic = v.getUint32(0, true);
  if (magic !== MAGIC && magic !== MAGIC_REVERSED && magic !== NVR_MAGIC) {
    return undefined;
  }
  const messageClass = v.getUint16(18, true);
  const hlen = headerLength(messageClass);
  const bodyLength = v.getUint32(8, true);
  if (bodyLength > 8_000_000) return undefined;
  if (buf.length - offset < hlen + bodyLength) return undefined;
  return {
    magic,
    id: v.getUint32(4, true),
    channelId: buf[offset + 12],
    streamId: buf[offset + 13],
    handle: v.getUint16(14, true),
    code: v.getUint16(16, true),
    messageClass,
    payloadOffset: hlen === 24 ? v.getUint32(20, true) : 0,
    body: buf.slice(offset + hlen, offset + hlen + bodyLength),
  };
}

/** Split a TCP buffer into frames. Returns consumed byte count. */
export function drainFrames(buf: Uint8Array): { frames: Frame[]; consumed: number } {
  const frames: Frame[] = [];
  let offset = 0;
  while (offset + 20 <= buf.length) {
    const magic = new DataView(buf.buffer, buf.byteOffset + offset, 4).getUint32(0, true);
    if (magic !== MAGIC && magic !== MAGIC_REVERSED && magic !== NVR_MAGIC) {
      offset++;
      continue;
    }
    const frame = decodeFrame(buf, offset);
    if (!frame) break;
    frames.push(frame);
    offset += headerLength(frame.messageClass) + frame.body.length;
  }
  return { frames, consumed: offset };
}
