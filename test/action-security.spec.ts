import { describe, expect, it } from "vitest";
// Vite bundles these artifacts as strings into the Workers test runtime.
// @ts-expect-error raw asset import
import action from "../github/action.yml?raw";
// @ts-expect-error raw asset import
import runtimePackageText from "../github/runtime/package.json?raw";
// @ts-expect-error raw asset import
import runtimeLock from "../github/runtime/bun.lock?raw";

const runtimePackage = JSON.parse(runtimePackageText);

describe("GitHub action dependency integrity", () => {
  it("pins setup-bun, Bun, and OpenCode to immutable inputs", () => {
    expect(action).toContain(
      "uses: oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6",
    );
    expect(action).toContain('bun-version: "1.3.14"');
    expect(action).toContain('default: "1.18.31"');
    expect(action).toContain("--frozen-lockfile --production");
    expect(action).not.toContain("bun install -g");

    expect(runtimePackage.dependencies).toEqual({ "opencode-ai": "1.18.31" });
    expect(runtimeLock).toContain(
      '"opencode-ai": ["opencode-ai@1.18.31", "",',
    );
    expect(runtimeLock).toMatch(/opencode-linux-x64@1\.18\.31[\s\S]*sha512-/);
  });
});
