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

  it("keeps the App token out of git config for NO_PUSH runs", () => {
    const configureGit = action.match(
      /    - name: Configure Git[\s\S]*?(?=\n    - name: Run opencode)/,
    )?.[0];

    expect(configureGit).toBeDefined();
    expect(configureGit).toContain(
      "TOKEN_PERMISSIONS: ${{ inputs.token_permissions }}",
    );
    expect(configureGit).toContain(
      'git config --unset-all "http.${server_url}/.extraheader" 2>/dev/null || true',
    );
    expect(configureGit).toContain(
      'normalized_permissions="${normalized_permissions#"${normalized_permissions%%[![:space:]]*}"}"',
    );
    expect(configureGit).toContain(
      'normalized_permissions="${normalized_permissions%"${normalized_permissions##*[![:space:]]}"}"',
    );
    expect(configureGit).toContain(
      `normalized_permissions="$(printf '%s' "\${normalized_permissions}" | tr '[:lower:]' '[:upper:]')"`,
    );
    expect(configureGit).toContain(
      'if [ "${normalized_permissions}" = "NO_PUSH" ]; then',
    );
    expect(configureGit).toContain(
      'git remote set-url origin "${server_url}/${GITHUB_REPOSITORY}.git"',
    );
    expect(configureGit).toContain('elif [ -n "${GH_TOKEN:-}" ]; then');

    const noPushBranch = configureGit!.indexOf(
      'if [ "${normalized_permissions}" = "NO_PUSH" ]; then',
    );
    const extraheaderRemoval = configureGit!.indexOf(
      'git config --unset-all "http.${server_url}/.extraheader" 2>/dev/null || true',
    );
    const credentialFreeRemote = configureGit!.indexOf(
      'git remote set-url origin "${server_url}/${GITHUB_REPOSITORY}.git"',
    );
    const writeBranch = configureGit!.indexOf(
      'elif [ -n "${GH_TOKEN:-}" ]; then',
    );
    const tokenizedRemote = configureGit!.indexOf(
      'git remote set-url origin "https://x-access-token:${GH_TOKEN}@${host}/${GITHUB_REPOSITORY}.git"',
    );
    expect(configureGit!.match(/x-access-token:\$\{GH_TOKEN\}/g)).toHaveLength(1);
    expect(extraheaderRemoval).toBeGreaterThan(-1);
    expect(extraheaderRemoval).toBeLessThan(noPushBranch);
    expect(noPushBranch).toBeGreaterThan(-1);
    expect(credentialFreeRemote).toBeGreaterThan(noPushBranch);
    expect(credentialFreeRemote).toBeLessThan(writeBranch);
    expect(writeBranch).toBeGreaterThan(noPushBranch);
    expect(tokenizedRemote).toBeGreaterThan(writeBranch);
  });
});
