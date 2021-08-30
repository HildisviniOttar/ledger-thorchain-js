import { extractSignatureFromTLV, getBech32FromPK } from "../../src/index";

describe("Helpers unit", () => {
  it("check address conversion", async () => {
    const pkStr = "0264bff60f78aae3326b4fc3e16a7c48d0158bfe175fa4a9361190a42565662ae6";
    const pk = Buffer.from(pkStr, "hex");
    const addr = getBech32FromPK("thor", pk);
    expect(addr).toEqual("thor1mwyrp6lj85swy5e5g4hjlaacm33g6rw3p4qmq4");
  });

  it("extractSignatureFromTLV", async () => {
    const from = [
      48, 69, 2, 33,
      0, 161, 207, 217, 127, 151, 190, 23, 98, 217, 186, 108, 82, 102, 19, 222, 20, 171, 6, 240, 134, 195, 251, 98, 190, 246, 228, 243, 215, 95, 166, 121, 165,
      2, 32,
      69, 188, 53,  213, 24, 9, 191, 90, 244, 21, 213, 146, 240, 109, 156, 221, 247, 63, 131, 52, 150, 253, 199, 153, 132, 76, 91, 239, 28, 254, 68, 80
    ];

    const to = [
      161, 207, 217, 127, 151, 190, 23, 98, 217, 186, 108, 82, 102, 19, 222, 20, 171, 6, 240, 134, 195, 251, 98, 190, 246, 228, 243, 215, 95, 166, 121, 165,
      69, 188, 53, 213, 24, 9, 191, 90, 244, 21, 213, 146, 240, 109, 156, 221, 247, 63, 131, 52, 150, 253, 199, 153, 132, 76, 91, 239, 28, 254, 68, 80
    ];

    const result = extractSignatureFromTLV(Buffer.from(from));
    expect(result.equals(Buffer.from(to))).toBeTruthy();

  });

});
