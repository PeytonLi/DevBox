import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const configuredPython = process.env.DEVBOX_PYTHON;
const candidates = configuredPython
  ? [configuredPython]
  : [
      join(repoRoot, ".venv", "Scripts", "python.exe"),
      join(repoRoot, ".venv", "bin", "python"),
    ];

const python = candidates.find((candidate) => existsSync(candidate));

if (!python) {
  console.error(
    "Could not find DevBox Python. Create a virtual environment at .venv or set DEVBOX_PYTHON.",
  );
  console.error("Example: python -m venv .venv");
  process.exit(1);
}

const child = spawn(python, process.argv.slice(2), {
  cwd: repoRoot,
  stdio: "inherit",
  windowsHide: false,
});

child.on("error", (error) => {
  console.error(error.message);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.exit(1);
  }

  process.exit(code ?? 0);
});
