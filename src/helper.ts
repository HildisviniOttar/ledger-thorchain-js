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
import { SignResponse } from "./types";

export function serializePathv2(path: number[]): Buffer {
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

async function signSendChunkv1(
  transport: Transport,
  chunkIdx: number,
  chunkNum: number,
  chunk: Buffer,
): Promise<SignResponse> {
  try {
    const response: Buffer = await transport.send(CLA, INS.SIGN_SECP256K1, chunkIdx, chunkNum, chunk, [
      LedgerErrorType.NoErrors,
      LedgerErrorType.DataIsInvalid,
      LedgerErrorType.BadKeyHandle,
    ]);

    const errorCodeData = response.slice(-2);
    const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
    let errorMessage = errorCodeToString(returnCode);

    if (returnCode === LedgerErrorType.BadKeyHandle || returnCode === LedgerErrorType.DataIsInvalid) {
      errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
    }

    if (response.length > 2) {
      return {
        returnCode,
        errorMessage,
        signature: response.slice(0, response.length - 2),
      };
    }

    throw new LedgerError(returnCode, errorMessage);
  } catch (error) {
    throw ledgerErrorFromResponse(error);
  }
}

export async function signSendChunkv2(
  transport: Transport,
  chunkIdx: number,
  chunkNum: number,
  chunk: Buffer,
) {
  let payloadType = PAYLOAD_TYPE.ADD;
  if (chunkIdx === 1) {
    payloadType = PAYLOAD_TYPE.INIT;
  }
  if (chunkIdx === chunkNum) {
    payloadType = PAYLOAD_TYPE.LAST;
  }

  return signSendChunkv1(transport, payloadType, 0, chunk);
}

export async function publicKeyv2(transport: Transport, data: Buffer) {
  try {
    const response = await transport.send(CLA, INS.GET_ADDR_SECP256K1, 0, 0, data, [
      LedgerErrorType.NoErrors,
    ]);
    const errorCodeData = response.slice(-2);
    const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
    const compressedPk = Buffer.from(response.slice(0, 33));

    return {
      pk: "OBSOLETE PROPERTY",
      compressed_pk: compressedPk,
      return_code: returnCode,
      error_message: errorCodeToString(returnCode),
    };
  } catch (error) {
    throw ledgerErrorFromResponse(error);
  }
}
