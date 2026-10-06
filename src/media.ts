import { MediaMagic } from "./commands.ts";

export type MediaKind = "info" | "iframe" | "pframe" | "aac" | "adpcm" | "unknown";

export interface MediaPacket {
  kind: MediaKind;
  magic: string;
  codec?: "H264" | "H265";
  width?: number;
  height?: number;
  fps?: number;
  payload: Uint8Array;
  microseconds?: number;
  unixTime?: number;
  headerLength: number;
}

const text = new TextDecoder();

function ascii(buf: Uint8Array, off: number, len: number): string {
  return text.decode(buf.subarray(off, off + len));
}

function u32(buf: Uint8Array, off: number): number {
  return new DataView(buf.buffer, buf.byteOffset + off, 4).getUint32(0, true);
}

function u16(buf: Uint8Array, off: number): number {
  return new DataView(buf.buffer, buf.byteOffset + off, 2).getUint16(0, true);
}

/** Parse one BcMedia block. Returns undefined if the buffer is shorter than the header. */
export function parseMediaPacket(buf: Uint8Array): MediaPacket | undefined {
  if (buf.length < 8) return undefined;
  const magic = ascii(buf, 0, 4);
  if (magic === MediaMagic.infoV1 || magic === MediaMagic.infoV2) {
    if (buf.length < 32) return undefined;
    const headerLength = u32(buf, 4) || 32;
    return {
      kind: "info",
      magic,
      width: u32(buf, 8),
      height: u32(buf, 12),
      fps: buf[17],
      payload: new Uint8Array(),
      headerLength,
    };
  }
  if (magic === MediaMagic.iFrame || magic === MediaMagic.pFrame) {
    const headerLength = magic === MediaMagic.iFrame ? 32 : 24;
    if (buf.length < headerLength) return undefined;
    const size = u32(buf, 8);
    const codecRaw = ascii(buf, 4, 4);
    const codec = codecRaw.startsWith("H265") ? "H265" : "H264";
    return {
      kind: magic === MediaMagic.iFrame ? "iframe" : "pframe",
      magic,
      codec,
      payload: buf.slice(headerLength, headerLength + size),
      microseconds: u32(buf, 16),
      unixTime: magic === MediaMagic.iFrame ? u32(buf, 24) : undefined,
      headerLength,
    };
  }
  if (magic === MediaMagic.aac || magic === MediaMagic.adpcm) {
    const size = u16(buf, 4);
    const headerLength = 8;
    if (buf.length < headerLength) return undefined;
    return {
      kind: magic === MediaMagic.aac ? "aac" : "adpcm",
      magic,
      payload: buf.slice(headerLength, headerLength + size),
      headerLength,
    };
  }
  return {
    kind: "unknown",
    magic,
    payload: buf.slice(4),
    headerLength: 4,
  };
}

/** Walk a reassembled binary payload and yield every recognised block. */
export function* demuxMedia(buf: Uint8Array): Generator<MediaPacket> {
  const magics = Object.values(MediaMagic);
  let i = 0;
  while (i + 8 <= buf.length) {
    const magic = ascii(buf, i, 4);
    if (!magics.includes(magic as typeof magics[number])) {
      i++;
      continue;
    }
    const packet = parseMediaPacket(buf.subarray(i));
    if (!packet) return;
    const size = packet.headerLength + packet.payload.length;
    if (size < 8) {
      i++;
      continue;
    }
    yield packet;
    i += size;
  }
}
