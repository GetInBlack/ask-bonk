#!/usr/bin/env bun

import { readFileSync } from "fs";

interface CredentialEnvironment {
  GH_TOKEN?: string;
  GITHUB_REPOSITORY?: string;
  GITHUB_SERVER_URL?: string;
}

function parseCredentialInput(input: string): Map<string, string> | null {
  const fields = new Map<string, string>();
  for (const line of input.split("\n")) {
    if (!line) continue;
    const separator = line.indexOf("=");
    if (separator <= 0) return null;
    const key = line.slice(0, separator);
    if (fields.has(key)) return null;
    fields.set(key, line.slice(separator + 1));
  }
  return fields;
}

export function buildCredentialResponse(
  operation: string | undefined,
  input: string,
  environment: CredentialEnvironment,
): string | null {
  if (operation !== "get") return "";

  const token = environment.GH_TOKEN;
  const repository = environment.GITHUB_REPOSITORY;
  const serverUrl = environment.GITHUB_SERVER_URL;
  if (!token || !repository || !serverUrl || /[\r\n]/.test(token)) return null;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) return null;

  let expectedHost: string;
  try {
    const parsedServer = new URL(serverUrl);
    if (
      parsedServer.protocol !== "https:" ||
      (parsedServer.pathname !== "/" && parsedServer.pathname !== "")
    ) {
      return null;
    }
    expectedHost = parsedServer.host;
  } catch {
    return null;
  }

  const fields = parseCredentialInput(input);
  if (!fields) return null;
  if (fields.get("protocol") !== "https") return null;
  if (fields.get("host") !== expectedHost) return null;

  const path = fields.get("path");
  if (path !== repository && path !== `${repository}.git`) return null;

  return `username=x-access-token\npassword=${token}\n\n`;
}

if (import.meta.main) {
  const response = buildCredentialResponse(process.argv[2], readFileSync(0, "utf8"), process.env);
  if (response === null) process.exit(1);
  process.stdout.write(response);
}
