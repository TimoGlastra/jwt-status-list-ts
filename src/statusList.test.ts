import { describe, test, expect } from "bun:test";
import { decodeStatusList, encodeStatusList } from "./statusList";

// https://datatracker.ietf.org/doc/html/draft-looker-oauth-jwt-cwt-status-list-01#name-example-status-list-with-2-
const list1Bit = {
  bits: [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1],
  encoded: "H4sIAMo_jGQC_9u5GABc9QE7AgAAAA",
};

// https://datatracker.ietf.org/doc/html/draft-looker-oauth-jwt-cwt-status-list-01#name-example-status-list-with-2-
const list2Bits = {
  bits: [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3],
  encoded: "H4sIAMo_jGQC_zvp8hMAZLRLMQMAAAA",
};

describe("jwtStatusList", () => {
  test("should encode jwt status list with bit size 1", () => {
    expect(encodeStatusList(list1Bit.bits, 1)).toBe(list1Bit.encoded);
  });

  test("should encode jwt status list with bit size 2", () => {
    expect(encodeStatusList(list2Bits.bits, 2)).toBe(list2Bits.encoded);
  });

  test("should decode jwt status list with bit size 1", () => {
    expect(decodeStatusList(list1Bit.encoded, 1)).toEqual(list1Bit.bits);
  });

  test("should decode jwt status list with bit size 2", () => {
    expect(decodeStatusList(list2Bits.encoded, 2)).toEqual(list2Bits.bits);
  });
});
