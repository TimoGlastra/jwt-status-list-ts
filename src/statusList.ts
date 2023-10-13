// https://datatracker.ietf.org/doc/html/draft-looker-oauth-jwt-cwt-status-list-01#name-status-claim-format
import { z } from "zod";

// NOTE: native gzip from Node.JS does not support MTIME, so we use fflate instead
// This should also make it work in any JS environment.
import { gzipSync, gunzipSync } from "fflate";

const zJwtStatusListBitSize = z.union([
  z.literal(1),
  z.literal(2),
  z.literal(4),
  z.literal(8),
]);
type JwtStatusListBitSize = z.infer<typeof zJwtStatusListBitSize>;

/**
 * Decodes the base64-url encoded, gzip compressed status list into an array of number values based on the bit size
 *
 * The bit size is specified in the JWT, and can be 1, 2, 4, or 8.
 * The bit size determines how many bits are used to represent each status value.
 * - 1 bit: 0-1
 * - 2 bits: 0-3
 * - 4 bits: 0-15
 * - 8 bits: 0-255
 */
export function decodeStatusList(
  list: string,
  bitSize: JwtStatusListBitSize
): Array<StatusListValueType | number> {
  const decodedList = gunzipSync(Buffer.from(list, "base64"));
  const output: Array<StatusListValueType | number> = [];

  const bits = Array.from(decodedList).flatMap((byte) =>
    byte
      .toString(2)
      .padStart(8, "0")
      .split("")
      .reverse()
      .map((bit) => parseInt(bit))
  );

  for (let bitIndex = 0; bitIndex < bits.length; bitIndex += bitSize) {
    const value = parseInt(
      bits
        .slice(bitIndex, bitIndex + bitSize)
        .reverse()
        .join(""),
      2
    );

    output.push(value);
  }

  return output;
}

/**
 * Encodes an array of number values into a base64-url encoded, gzip compressed string based on the bit size
 *
 * The bit size is specified in the JWT, and can be 1, 2, 4, or 8.
 * The bit size determines how many bits are used to represent each status value.
 * - 1 bit: 0-1
 * - 2 bits: 0-3
 * - 4 bits: 0-15
 * - 8 bits: 0-255
 *
 * @throws when the bitSize is too small for a number value present in the list.
 */
export function encodeStatusList(
  list: Array<StatusListValueType | number>,
  bitSize: JwtStatusListBitSize
): string {
  const bits: number[] = [];

  // Transform the value into bits
  for (const value of list) {
    // value can't exceed bitSize
    if (value > 2 ** bitSize - 1) {
      throw new Error(`Value ${value} is too large for bit size ${bitSize}`);
    }

    bits.push(
      ...(value >>> 0)
        .toString(2)
        .padStart(bitSize, "0")
        .split("")
        .map((bit) => parseInt(bit))
        .reverse()
    );
  }

  // TODO: we could probably optimize this and do it in one loop
  // Transform the bits into a Uint8Array
  const buffer = new Uint8Array(Math.ceil(bits.length / 8));
  for (let bitIndex = 0; bitIndex < bits.length; bitIndex += 8) {
    const byte = bits
      .slice(bitIndex, bitIndex + 8)
      .reverse()
      .join("");

    buffer.set([parseInt(byte, 2)], bitIndex / 8);
  }

  const zipped = gzipSync(buffer, {
    // FIXME: level and mtime are from reference implementation, to check for compatibility
    mtime: new Date(1686912970 * 1000),
    level: 9,
  });

  // Encode and compress the Uint8Array
  return Buffer.from(zipped).toString("base64url");
}

export enum StatusListValueType {
  /* The status of the Token is valid, correct or legal. */
  VALID = 0,

  /* The status of the Token is revoked, annulled, taken back, recalled or cancelled. */
  INVALID = 1,

  /* The status of the Token is temporarily invalid, hanging, debarred from privilege. This state is reversible. */
  SUSPENDED = 2,
}
