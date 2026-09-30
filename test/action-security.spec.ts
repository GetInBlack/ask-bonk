import { describe, expect, it } from "vitest";
// Vite bundles these artifacts as strings into the Workers test runtime.
// @ts-expect-error raw asset import
import action from "../github/action.yml?raw";
// @ts-expect-error raw asset import
import runtimePackageText from "../github/runtime/package.json?raw";
// @ts-expect-error raw asset import
import runtimeLock from "../github/runtime/bun.lock?raw";
import { buildCredentialResponse } from "../github/script/git-credential-readonly";

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
    expect(configureGit).toContain('echo "read_only=true" >> "${GITHUB_OUTPUT}"');
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
    const readOnlyOutput = configureGit!.indexOf('echo "read_only=true" >> "${GITHUB_OUTPUT}"');
    expect(configureGit!.match(/x-access-token:\$\{GH_TOKEN\}/g)).toHaveLength(1);
    expect(extraheaderRemoval).toBeGreaterThan(-1);
    expect(extraheaderRemoval).toBeLessThan(noPushBranch);
    expect(noPushBranch).toBeGreaterThan(-1);
    expect(credentialFreeRemote).toBeGreaterThan(noPushBranch);
    expect(readOnlyOutput).toBeGreaterThan(credentialFreeRemote);
    expect(readOnlyOutput).toBeLessThan(writeBranch);
    expect(credentialFreeRemote).toBeLessThan(writeBranch);
    expect(writeBranch).toBeGreaterThan(noPushBranch);
    expect(tokenizedRemote).toBeGreaterThan(writeBranch);
  });

  it("scopes the read-only credential helper to the OpenCode step", () => {
    const runOpenCode = action.match(
      /    - name: Run opencode[\s\S]*?(?=\n    - name: Finalize Bonk run)/,
    )?.[0];

    expect(runOpenCode).toBeDefined();
    expect(runOpenCode).toContain("READ_ONLY_GIT: ${{ steps.configure_git.outputs.read_only }}");
    const readOnlyBlock = runOpenCode!.match(
      /        if \[ "\$\{READ_ONLY_GIT\}" = "true" \]; then\n([\s\S]*?)\n        fi/,
    )?.[1];
    expect(readOnlyBlock).toBeDefined();
    expect(readOnlyBlock).toContain('export GIT_CONFIG_VALUE_0=""');
    expect(readOnlyBlock).toContain('export GIT_CONFIG_KEY_1="credential.useHttpPath"');
    expect(readOnlyBlock).toContain('export GIT_CONFIG_KEY_2="core.askPass"');
    expect(readOnlyBlock).toContain('export GIT_CONFIG_VALUE_2="/bin/false"');
    expect(readOnlyBlock).toContain(
      'export GIT_CONFIG_VALUE_3="!${GITHUB_ACTION_PATH}/script/git-credential-readonly.ts"',
    );
    expect(readOnlyBlock).toContain("export GIT_ASKPASS=/bin/false");
    expect(readOnlyBlock).toContain("export SSH_ASKPASS=/bin/false");
    expect(readOnlyBlock).toContain("export GIT_TERMINAL_PROMPT=0");
    expect(runOpenCode).not.toContain('>> "${GITHUB_ENV}"');
  });

  it("returns the dedicated token only for the exact GitHub repository", () => {
    const environment = {
      GH_TOKEN: "dummy-read-only-token",
      GITHUB_REPOSITORY: "GetInBlack/private-repo",
      GITHUB_SERVER_URL: "https://github.com",
    };
    const valid = "protocol=https\nhost=github.com\npath=GetInBlack/private-repo.git\n\n";
    const gitCredentialV2 =
      'capability[]=authtype\ncapability[]=state\nprotocol=https\nhost=github.com\npath=GetInBlack/private-repo.git\nwwwauth[]=Basic realm="GitHub"\n\n';

    expect(buildCredentialResponse("get", valid, environment)).toBe(
      "username=x-access-token\npassword=dummy-read-only-token\n\n",
    );
    expect(buildCredentialResponse("get", gitCredentialV2, environment)).toBe(
      "username=x-access-token\npassword=dummy-read-only-token\n\n",
    );
    expect(
      buildCredentialResponse(
        "get",
        "protocol=https\nprotocol=http\nhost=github.com\npath=GetInBlack/private-repo.git\n\n",
        environment,
      ),
    ).toBeNull();
    expect(
      buildCredentialResponse(
        "get",
        "protocol=https\nhost=attacker.example\npath=GetInBlack/private-repo.git\n\n",
        environment,
      ),
    ).toBeNull();
    expect(
      buildCredentialResponse(
        "get",
        "protocol=https\nhost=github.com\npath=attacker/repo.git\n\n",
        environment,
      ),
    ).toBeNull();
    expect(
      buildCredentialResponse(
        "get",
        "protocol=http\nhost=github.com\npath=GetInBlack/private-repo.git\n\n",
        environment,
      ),
    ).toBeNull();
    expect(
      buildCredentialResponse("get", valid, { ...environment, GH_TOKEN: undefined }),
    ).toBeNull();
    expect(
      buildCredentialResponse("get", valid, {
        ...environment,
        GH_TOKEN: undefined,
        GITHUB_TOKEN: "broader-caller-token",
      } as typeof environment & { GITHUB_TOKEN: string }),
    ).toBeNull();
    expect(buildCredentialResponse("store", valid, environment)).toBe("");
  });
});
