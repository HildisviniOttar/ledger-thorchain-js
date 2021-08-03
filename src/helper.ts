import type Transport from "@ledgerhq/hw-transport";
import {
  CLA,
  errorCodeToString,
  INS,
  LedgerError,
  LedgerErrorType,
  PAYLOAD_TYPE,
  ledgerErrorFromResponse,
} from "./common";
import crypto from "crypto";
import Ripemd160 from "ripemd160";
import { bech32 } from "bech32";
import { PubKeyResponse, SignResponse, VersionResponse } from "./types";

export function serializeHRP(hrp: string): Buffer {
  if (!hrp || hrp.length < 3 || hrp.length > 83) {
    throw new LedgerError(LedgerErrorType.HPRInvalid);
  }
  const buf = Buffer.alloc(1 + hrp.length);
  buf.writeUInt8(hrp.length, 0);
  buf.write(hrp, 1);
  return buf;
}

export function getBech32FromPK(hrp: string, pk: Buffer): string {
  if (pk.length !== 33) {
    throw new LedgerError(LedgerErrorType.PKInvalidBytes);
  }

  const hashSha256 = crypto.createHash("sha256").update(pk).digest();
  const hashRip = new Ripemd160().update(hashSha256).digest();
  const words = bech32.toWords(hashRip);
  return bech32.encode(hrp, words);
}

export function serializePath(path: number[]): Buffer {
  if (!path || path.length !== 5) {
    throw new Error("Invalid path.");
  }

  const buf = Buffer.alloc(20);
  buf.writeUInt32LE(0x80000000 + path[0], 0);
  buf.writeUInt32LE(0x80000000 + path[1], 4);
  buf.writeUInt32LE(0x80000000 + path[2], 8);
  buf.writeUInt32LE(path[3], 12);
  buf.writeUInt32LE(path[4], 16);

  return buf;
}

export async function signSendChunk(
  transport: Transport,
  chunkIdx: number,
  chunkNum: number,
  chunk: Buffer,
): Promise<SignResponse> {
  let payloadType = PAYLOAD_TYPE.ADD;
  if (chunkIdx === 1) {
    payloadType = PAYLOAD_TYPE.INIT;
  }
  if (chunkIdx === chunkNum) {
    payloadType = PAYLOAD_TYPE.LAST;
  }

  const response: Buffer = await transport.send(CLA, INS.SIGN_SECP256K1, payloadType, 0, chunk, [
    LedgerErrorType.NoErrors,
    LedgerErrorType.DataIsInvalid,
    LedgerErrorType.BadKeyHandle,
    LedgerErrorType.SignVerifyError,
  ]);

  const errorCodeData = response.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
  let errorMessage = errorCodeToString(returnCode);

  if (
    returnCode === LedgerErrorType.BadKeyHandle ||
    returnCode === LedgerErrorType.DataIsInvalid ||
    returnCode === LedgerErrorType.SignVerifyError
  ) {
    errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
    throw new LedgerError(returnCode, errorMessage);
  }

  if (returnCode === LedgerErrorType.NoErrors && response.length > 2) {
    return {
      returnCode,
      errorMessage,
      signature: response.slice(0, response.length - 2),
    };
  }

  return {
    returnCode,
    errorMessage,
  };
}

export async function getVersion(transport: Transport): Promise<VersionResponse> {
  try {
    const response: Buffer = await transport.send(CLA, INS.GET_VERSION, 0, 0);

    const errorCodeData = response.slice(-2);
    const returnCode = (errorCodeData[0] * 256 + errorCodeData[1]) as LedgerErrorType;

    let targetId = 0;
    if (response.length >= 9) {
      /* eslint-disable no-bitwise */
      targetId = (response[5] << 24) + (response[6] << 16) + (response[7] << 8) + (response[8] << 0);
      /* eslint-enable no-bitwise */
    }

    return {
      returnCode,
      errorMessage: errorCodeToString(returnCode),
      testMode: response[0] !== 0,
      major: response[1],
      minor: response[2],
      patch: response[3],
      deviceLocked: response[4] === 1,
      targetId: targetId.toString(16),
    };
  } catch (error) {
    throw ledgerErrorFromResponse(error);
  }
}

export async function getPublicKey(transport: Transport, data: Buffer): Promise<PubKeyResponse> {
  try {
    const response = await transport.send(CLA, INS.GET_ADDR_SECP256K1, 0, 0, data, [
      LedgerErrorType.NoErrors,
    ]);
    const errorCodeData = response.slice(-2);
    const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
    const compressedPk = Buffer.from(response.slice(0, 33));

    return {
      compressedPk,
      returnCode,
      errorMessage: errorCodeToString(returnCode),
    };
  } catch (error) {
    throw ledgerErrorFromResponse(error);
  }
}

/**
 * Takes raw output from Ledger device which is TLV encoded in the format "0x30 L 0x02 Lr r 0x02 Ls s"
 * where L is length of entire message (after 2nd byte), Lr is length of r and Ls is length of s.
 * This function extracts r and s, ensures they are 32 bytes each, joins into a single 64 byte Array.
 * This value returned should be base64 encoded to a string to add to the JSON 'signatures' to send to RPC.
 *
 * Example raw sig:
 * [ 48, 69, 2, 33,
 *   0, 161, 207, 217, 127, 151, 190, 23, 98, 217, 186, 108, 82, 102, 19, 222, 20, 171, 6, 240, 134, 195, 251, 98, 190, 246, 228, 243, 215, 95, 166, 121, 165,
 *   2, 32,
 *   69, 188, 53,  213, 24, 9, 191, 90, 244, 21, 213, 146, 240, 109, 156, 221, 247, 63, 131, 52, 150, 253, 199, 153, 132, 76, 91, 239, 28, 254, 68, 80 ]
 *
 *   48 69  -- length is 69
 *   2 33   -- length of r is 33 bytes
 *   <33 bytes of r>  -- (the leading zero here can be dropped)
 *   2 32   -- length of s is 32 bytes
 *   <32 bytes of s>
 */
export function extractSignatureFromTLV(signatureArray: number[]): number[] {
  // Check Type Length Value encoding
  if (signatureArray.length < 64) {
    throw Error("Invalid Signature: Too short");
  }
  if (signatureArray[0] != 0x30) {
    throw Error("Invalid Ledger Signature TLV encoding: expected first byte 0x30");
  }
  if (signatureArray[1] + 2 != signatureArray.length) {
    throw Error("Invalid Signature: signature length does not match TLV");
  }
  if (signatureArray[2] != 0x02) {
    throw Error("Invalid Ledger Signature TLV encoding: expected length type 0x02");
  }

  // r signature
  const rLength = signatureArray[3];
  var rSignature = signatureArray.slice(4, rLength + 4);
  // Drop leading zero on some 'r' signatures that are 33 bytes.
  if (rSignature.length == 33 && rSignature[0] == 0) {
    rSignature = rSignature.slice(1, 33);
  } else if (rSignature.length == 33) {
    throw Error('Invalid signature: "r" too long');
  }
  // add leading zero's to pad to 32 bytes
  while (rSignature.length < 32) {
    rSignature.unshift(0);
  }

  // s signature
  if (signatureArray[rLength + 4] != 0x02) {
    throw Error("Invalid Ledger Signature TLV encoding: expected length type 0x02");
  }
  const sLength = signatureArray[rLength + 5];
  if (4 + rLength + 2 + sLength != signatureArray.length) {
    throw Error("Invalid Ledger Signature: TLV byte lengths do not match message length");
  }
  var sSignature = signatureArray.slice(rLength + 6, signatureArray.length);
  // Drop leading zero on 's' signatures that are 33 bytes. This shouldn't occur since ledger signs using "Small s" math. But just to be sure...
  if (sSignature.length == 33 && sSignature[0] == 0) {
    sSignature = sSignature.slice(1, 33);
  } else if (sSignature.length == 33) {
    throw Error('Invalid signature: "s" too long');
  }
  // add leading zero's to pad to 32 bytes
  while (sSignature.length < 32) {
    sSignature.unshift(0);
  }

  if (rSignature.length != 32 || sSignature.length != 32) {
    throw Error("Invalid signatures: must be 32 bytes each");
  }

  return rSignature.concat(sSignature);
}
