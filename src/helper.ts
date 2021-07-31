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
