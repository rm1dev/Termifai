/**
 * Smoke test: POSIX shell quoting must neutralize metacharacters used in
 * remote bootstrap `cd` paths (SSH workingDirectory injection guard).
 * Run: node scripts/validate-shell-quote.mjs
 */

function posixShellQuote(value) {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function buildCdPart(workingDirectory) {
  const trimmed = workingDirectory?.trim();
  return trimmed ? `cd ${posixShellQuote(trimmed)} 2>/dev/null; ` : "";
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const injection = "/tmp; touch /tmp/pwned; #";
const quoted = buildCdPart(injection);
assert(quoted.includes(posixShellQuote(injection)), "cd path must be quoted");
assert(!quoted.includes("cd /tmp; touch"), "raw metacharacters must not appear unquoted");
assert(
  quoted === `cd '/tmp; touch /tmp/pwned; #' 2>/dev/null; `,
  `unexpected cdPart: ${quoted}`
);

const withSpace = buildCdPart("/home/user/My Docs");
assert(
  withSpace === `cd '/home/user/My Docs' 2>/dev/null; `,
  `spaces must stay inside quotes: ${withSpace}`
);

const withQuote = buildCdPart("/tmp/it's");
assert(
  withQuote === `cd '/tmp/it'\\''s' 2>/dev/null; `,
  `embedded single quotes must be escaped: ${withQuote}`
);

assert(buildCdPart(undefined) === "", "missing working dir yields empty cdPart");
assert(buildCdPart("   ") === "", "whitespace-only working dir yields empty cdPart");

/** Mirrors src/lib/shell-quote.ts `sshCliDestination`. */
function sshCliDestination(user, hostname) {
  return `-- ${posixShellQuote(`${user}@${hostname}`)}`;
}

const dest = sshCliDestination("ubuntu", "example.com");
assert(dest.startsWith("-- "), "destination must start with --");
assert(
  dest === `-- ${posixShellQuote("ubuntu@example.com")}`,
  `unexpected destination: ${dest}`
);

const injectedUser = "-oProxyCommand=touch /tmp/pwned";
const injected = sshCliDestination(injectedUser, "127.0.0.1");
assert(injected.startsWith("-- "), "leading-dash user still gets -- prefix");
assert(
  injected.includes(posixShellQuote(`${injectedUser}@127.0.0.1`)),
  "leading-dash user must be inside the quoted destination"
);
assert(!injected.startsWith("-o"), "must not expose bare -o before --");

console.log("validate-shell-quote: ok");
