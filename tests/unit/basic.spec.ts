import { getBech32FromPK } from "../../src/index";

describe("Helpers unit", () => {
  it("check address conversion", async () => {
    const pkStr = "0264bff60f78aae3326b4fc3e16a7c48d0158bfe175fa4a9361190a42565662ae6";
    const pk = Buffer.from(pkStr, "hex");
    const addr = getBech32FromPK("thor", pk);
    expect(addr).toEqual("thor1mwyrp6lj85swy5e5g4hjlaacm33g6rw3p4qmq4");
  });
});
