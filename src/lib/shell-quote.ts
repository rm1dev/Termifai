import { platform } from "@/lib/platform";

/** Quotes a value for POSIX shells (bash/zsh/sh), escaping embedded single quotes. */
export function posixShellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/**
 * Quotes a filesystem path for the current OS's default shell. Windows
 * filenames can't contain `"`, so a plain double-quote wrap is safe there
 * for both PowerShell and cmd.exe; POSIX shells need the fuller escaping
 * since `'` is a valid path character.
 */
export function quotePathForShell(path: string): string {
  return platform === "windows" ? `"${path}"` : posixShellQuote(path);
}

/**
 * OpenSSH destination segment for a locally-spawned `ssh` command line.
 * Always includes `--` so a leading-dash username (e.g. `-oProxyCommand=…`)
 * cannot be parsed as an OpenSSH option — shell quoting alone does not stop that.
 */
export function sshCliDestination(user: string, hostname: string): string {
  return `-- ${posixShellQuote(`${user}@${hostname}`)}`;
}
