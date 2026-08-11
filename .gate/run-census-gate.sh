#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

GATE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly GATE_DIR
CENSUS_ROOT="$(cd -- "${GATE_DIR}/.." && pwd -P)"
readonly CENSUS_ROOT
readonly ARTIFACT_DIR="${GATE_DIR}/artifacts"
readonly CERT_DIR="${GATE_DIR}/.cert"
readonly BASE="https://127.0.0.1:8443"
readonly FIXTURE_BIN="${CENSUS_ROOT}/target/release/census_fixture"
readonly PLAYWRIGHT_VERSION="1.60.0"
readonly AXE_VERSION="4.12.1"
readonly -a SCENARIOS=(
  populated
  empty
  no-results
  identity-unavailable
  profile-unavailable
  group-unavailable
  both-unavailable
  n1999
  n2000
  n2001
  hostile-data
  missing-identity
)

fixture_pid=""
shim_pid=""
success=0
gate_rc=0

stop_process() {
  local pid="${1:-}"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    kill -TERM "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
}

cleanup() {
  local rc=$?
  stop_process "${fixture_pid}"
  stop_process "${shim_pid}"
  if [[ -d "${CERT_DIR}" ]]; then
    chmod -R u+rwX "${CERT_DIR}" 2>/dev/null || true
    rm -rf -- "${CERT_DIR}"
  fi
  if [[ "${success}" -eq 1 ]]; then
    rm -rf -- "${ARTIFACT_DIR}"
    printf 'Census gate passed; ephemeral artifacts were removed.\n'
  elif [[ -d "${ARTIFACT_DIR}" ]]; then
    printf 'Census gate failed; evidence retained at %s\n' "${ARTIFACT_DIR}" >&2
  fi
  if [[ "${rc}" -ne 0 ]]; then
    exit "${rc}"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

for command in cargo node npm openssl curl sha256sum; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    printf 'Census gate requires %s in PATH.\n' "${command}" >&2
    exit 69
  fi
done

if [[ -L "${GATE_DIR}/package-lock.json" || ! -f "${GATE_DIR}/package-lock.json" ]]; then
  printf 'Census gate package-lock.json must be a committed, non-symlink regular file.\n' >&2
  exit 65
fi

rm -rf -- "${ARTIFACT_DIR}"
mkdir -p -- "${ARTIFACT_DIR}" "${CERT_DIR}"
chmod 700 "${CERT_DIR}"

printf 'Building the synthetic Census fixture binary...\n'
(cd -- "${CENSUS_ROOT}" && cargo build --release --locked --bin census_fixture)

lock_before="$(sha256sum "${GATE_DIR}/package-lock.json" | cut -d' ' -f1)"
printf 'Reproducing Playwright %s from the offline npm cache...\n' "${PLAYWRIGHT_VERSION}"
if ! (
  cd -- "${GATE_DIR}"
  npm_config_offline=true \
  npm_config_audit=false \
  npm_config_fund=false \
  npm_config_update_notifier=false \
    npm ci --offline --ignore-scripts --no-audit --no-fund
); then
  printf '%s\n' \
    "Census gate stopped: the exact @playwright/test ${PLAYWRIGHT_VERSION} and axe-core ${AXE_VERSION} integrity graph is absent from the local npm cache." \
    "Populate that cache through the separately controlled dependency-staging process; this gate will not use the network, an unpinned package, or another project's node_modules." >&2
  exit 69
fi
lock_after="$(sha256sum "${GATE_DIR}/package-lock.json" | cut -d' ' -f1)"
if [[ "${lock_before}" != "${lock_after}" ]]; then
  printf 'Census gate stopped: npm mutated the committed lockfile.\n' >&2
  exit 65
fi

installed_version="$(node -p "require('${GATE_DIR}/node_modules/@playwright/test/package.json').version")"
if [[ "${installed_version}" != "${PLAYWRIGHT_VERSION}" ]]; then
  printf 'Census gate stopped: expected Playwright %s, installed %s.\n' "${PLAYWRIGHT_VERSION}" "${installed_version}" >&2
  exit 65
fi
installed_axe_version="$(node -p "require('${GATE_DIR}/node_modules/axe-core/package.json').version")"
if [[ "${installed_axe_version}" != "${AXE_VERSION}" ]]; then
  printf 'Census gate stopped: expected axe-core %s, installed %s.\n' "${AXE_VERSION}" "${installed_axe_version}" >&2
  exit 65
fi
browser_path="$(cd -- "${GATE_DIR}" && node -e "import('playwright').then(({chromium}) => process.stdout.write(chromium.executablePath()))")"
if [[ ! -x "${browser_path}" ]]; then
  printf 'Census gate stopped: pinned Chromium executable is absent at %s. No browser download is permitted.\n' "${browser_path}" >&2
  exit 69
fi

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout "${CERT_DIR}/key.pem" \
  -out "${CERT_DIR}/cert.pem" \
  -days 1 \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" \
  >"${ARTIFACT_DIR}/openssl.log" 2>&1
chmod 600 "${CERT_DIR}/key.pem" "${CERT_DIR}/cert.pem"

CENSUS_TLS_CERT="${CERT_DIR}/cert.pem" \
CENSUS_TLS_KEY="${CERT_DIR}/key.pem" \
  node "${GATE_DIR}/tls-shim.mjs" >"${ARTIFACT_DIR}/tls-shim.log" 2>&1 &
shim_pid=$!

poll_health() {
  local attempt
  for ((attempt = 1; attempt <= 100; attempt++)); do
    if ! kill -0 "${shim_pid}" 2>/dev/null || ! kill -0 "${fixture_pid}" 2>/dev/null; then
      return 1
    fi
    if [[ "$(curl --silent --show-error --insecure --max-time 1 "${BASE}/healthz" 2>/dev/null || true)" == "ok" ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

for scenario in "${SCENARIOS[@]}"; do
  scenario_dir="${ARTIFACT_DIR}/${scenario}"
  mkdir -p -- "${scenario_dir}"
  printf 'Running synthetic Census scenario: %s\n' "${scenario}"
  CENSUS_FIXTURE="${scenario}" "${FIXTURE_BIN}" >"${scenario_dir}/fixture.log" 2>&1 &
  fixture_pid=$!

  if ! poll_health; then
    printf 'Scenario %s did not reach TLS /healthz=200 within 10 seconds.\n' "${scenario}" >&2
    gate_rc=1
    stop_process "${fixture_pid}"
    fixture_pid=""
    continue
  fi

  if ! (
    cd -- "${GATE_DIR}"
    env \
    BASE="${BASE}" \
    CENSUS_SCENARIO="${scenario}" \
    GATE_ARTIFACTS="${ARTIFACT_DIR}" \
      ./node_modules/.bin/playwright test --config="${GATE_DIR}/playwright.config.mjs"
  ); then
    gate_rc=1
  fi

  stop_process "${fixture_pid}"
  fixture_pid=""
done

stop_process "${shim_pid}"
shim_pid=""

if ! node --input-type=module - "${ARTIFACT_DIR}" "${PLAYWRIGHT_VERSION}" "${AXE_VERSION}" <<'NODE'
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(process.argv[2]);
const playwrightVersion = process.argv[3];
const axeVersion = process.argv[4];
const scenarios = [
  "populated", "empty", "no-results", "identity-unavailable", "profile-unavailable",
  "group-unavailable", "both-unavailable", "n1999", "n2000", "n2001",
  "hostile-data", "missing-identity",
];
const widths = [320, 390, 768, 1024, 1440];
const failures = [];
const cells = [];

const sha256 = (data) => crypto.createHash("sha256").update(data).digest("hex");
const walk = (directory) => fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
  const absolute = path.join(directory, entry.name);
  return entry.isDirectory() ? walk(absolute) : [absolute];
});

for (const scenario of scenarios) {
  const directory = path.join(root, scenario);
  if (!fs.existsSync(directory)) {
    failures.push(`missing scenario artifacts: ${scenario}`);
    continue;
  }
  for (const fragment of walk(directory).filter((file) => file.endsWith(".fragment.json"))) {
    try {
      const parsed = JSON.parse(fs.readFileSync(fragment, "utf8"));
      if (parsed.scenario !== scenario || !Array.isArray(parsed.cells)) failures.push(`invalid fragment shape: ${fragment}`);
      else cells.push(...parsed.cells);
    } catch (error) {
      failures.push(`invalid fragment JSON ${fragment}: ${error.message}`);
    }
  }
}

const expectedKeys = new Set();
for (const scenario of scenarios) {
  for (const width of widths) {
    for (const js of [true, false]) {
      for (const capability of ["baseline", "cssOff", "forcedColors", "grayscale", "reducedMotion", "osDark"]) {
        expectedKeys.add([scenario, width, js, 100, capability].join("|"));
      }
      if (width === 1440) {
        expectedKeys.add([scenario, width, js, 200, "baseline"].join("|"));
        expectedKeys.add([scenario, width, js, 400, "baseline"].join("|"));
      }
    }
  }
}

const actualKeys = new Set();
for (const cell of cells) {
  const enabled = ["cssOff", "forcedColors", "grayscale", "reducedMotion", "osDark"].filter((field) => cell[field]);
  const capability = enabled[0] || "baseline";
  const key = [cell.scenario, cell.viewport, cell.js, cell.zoom, capability].join("|");
  if (actualKeys.has(key)) failures.push(`duplicate cell: ${key}`);
  actualKeys.add(key);
  if (enabled.length > 1) failures.push(`cell combines orthogonal capabilities: ${key}`);
  if (!expectedKeys.has(key)) failures.push(`unexpected cell: ${key}`);
  if (cell.httpStatus !== 200) failures.push(`${key}: httpStatus=${cell.httpStatus}`);
  if (cell.cacheControl !== "private, no-store") failures.push(`${key}: cacheControl=${cell.cacheControl}`);
  if (cell.varyPresent !== false) failures.push(`${key}: Vary present`);
  if (!Number.isInteger(cell.navigationRetries) || cell.navigationRetries < 0 || cell.navigationRetries > 2) {
    failures.push(`${key}: invalid navigationRetries=${cell.navigationRetries}`);
  }
  if (cell.axeVersion !== axeVersion) failures.push(`${key}: axeVersion=${cell.axeVersion ?? "missing"}`);
  if (cell.axeCompleted !== true) failures.push(`${key}: axe audit incomplete`);
  if (cell.contractA11yCompleted !== true) failures.push(`${key}: contract a11y audit incomplete`);
  const expectedDisabledRules = cell.cssOff ? ["target-size"] : [];
  if (JSON.stringify(cell.axeRunProfile?.disabledRules) !== JSON.stringify(expectedDisabledRules)) {
    failures.push(`${key}: unexpected axe disabled rules`);
  }
  const expectedInstrumentation = cell.js
    ? "page-init-script"
    : "serialized-no-js-dom-in-isolated-axe-context";
  if (cell.axeRunProfile?.instrumentation !== expectedInstrumentation) {
    failures.push(`${key}: unexpected axe instrumentation`);
  }
  const sourceHash = cell.axeRunProfile?.sourceHtmlSha256;
  if (cell.js ? sourceHash !== null : !/^[a-f0-9]{64}$/.test(sourceHash || "")) {
    failures.push(`${key}: invalid no-JS source HTML identity`);
  }
  for (const field of ["consoleErrors", "pageErrors", "axeViolations", "contractA11yViolations", "forbiddenStrings"]) {
    if (cell[field] !== 0) failures.push(`${key}: ${field}=${cell[field]}`);
  }
  if (cell.piiLeak !== false) failures.push(`${key}: piiLeak=${cell.piiLeak}`);
  if (!Array.isArray(cell.failures) || cell.failures.length !== 0) failures.push(`${key}: cell failures present`);

  for (const name of ["screenshot", "aria", "http"]) {
    const record = cell.artifacts?.[name];
    if (!record || typeof record.path !== "string" || typeof record.sha256 !== "string") {
      failures.push(`${key}: missing ${name} artifact record`);
      continue;
    }
    const absolute = path.resolve(root, cell.scenario, record.path);
    const scenarioRoot = `${path.resolve(root, cell.scenario)}${path.sep}`;
    if (!absolute.startsWith(scenarioRoot) || !fs.existsSync(absolute)) {
      failures.push(`${key}: unsafe or missing ${name} artifact`);
      continue;
    }
    const artifactData = fs.readFileSync(absolute);
    const actual = sha256(artifactData);
    if (actual !== record.sha256) failures.push(`${key}: ${name} hash mismatch`);
    if (name === "http") {
      try {
        const http = JSON.parse(artifactData.toString("utf8"));
        if (http.a11yEngine?.axeCore !== axeVersion) failures.push(`${key}: HTTP artifact axe engine mismatch`);
        if (JSON.stringify(http.axeRunProfile) !== JSON.stringify(cell.axeRunProfile)) {
          failures.push(`${key}: HTTP artifact axe profile mismatch`);
        }
        if (http.navigationRetries !== cell.navigationRetries) {
          failures.push(`${key}: HTTP artifact navigation retry mismatch`);
        }
        if (!Array.isArray(http.axeViolations) || http.axeViolations.length !== cell.axeViolations) {
          failures.push(`${key}: HTTP artifact axe violation count mismatch`);
        }
        if (!Array.isArray(http.contractA11yViolations)
          || http.contractA11yViolations.length !== cell.contractA11yViolations) {
          failures.push(`${key}: HTTP artifact contract a11y count mismatch`);
        }
      } catch (error) {
        failures.push(`${key}: invalid HTTP artifact JSON: ${error.message}`);
      }
    }
  }
}

for (const key of expectedKeys) if (!actualKeys.has(key)) failures.push(`missing cell: ${key}`);

const secretRules = [
  ["authorization", /\bBearer\s+[A-Za-z0-9._~+/=-]+/i],
  ["csrf-cookie", /__Host-csrf\s*=/i],
  ["csrf-field", /csrf_token\s*[=:]\s*["']?[A-Za-z0-9_-]{8,}/i],
  ["gateway-header", /x-auth-(?:subject|email|scope)\s*[=:]/i],
  ["driver-detail", /\b(?:sqlx|tokio-postgres|postgres(?:ql)?\s+(?:driver|error))\b/i],
  ["secret-url", /[?&](?:access[_-]?token|api[_-]?key|secret|password|credential)=[^&#\s]+/i],
];
for (const file of walk(root).filter(
  (item) => !item.endsWith("results.json") && !item.endsWith(".png"),
)) {
  const text = fs.readFileSync(file).toString("utf8");
  for (const [name, rule] of secretRules) if (rule.test(text)) failures.push(`${path.relative(root, file)}: ${name} leak`);
  for (const match of text.matchAll(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/gi)) {
    if (!match[1].toLowerCase().endsWith("example.invalid")) failures.push(`${path.relative(root, file)}: non-synthetic email`);
  }
}

cells.sort((a, b) =>
  a.scenario.localeCompare(b.scenario)
  || a.viewport - b.viewport
  || Number(a.js) - Number(b.js)
  || a.zoom - b.zoom
  || Number(a.forcedColors) - Number(b.forcedColors)
  || Number(a.grayscale) - Number(b.grayscale)
  || Number(a.reducedMotion) - Number(b.reducedMotion)
  || Number(a.osDark) - Number(b.osDark)
  || Number(a.cssOff) - Number(b.cssOff));

const completedAxeScans = cells.filter(
  (cell) => cell.axeCompleted === true && cell.axeVersion === axeVersion,
).length;
const completedContractScans = cells.filter((cell) => cell.contractA11yCompleted === true).length;
if (completedAxeScans !== expectedKeys.size) failures.push(`completed axe scans=${completedAxeScans}/${expectedKeys.size}`);
if (completedContractScans !== expectedKeys.size) {
  failures.push(`completed contract a11y scans=${completedContractScans}/${expectedKeys.size}`);
}

const result = {
  schemaVersion: "w33d.census.browser-gate.v2",
  generatedAt: new Date().toISOString(),
  syntheticOnly: true,
  hmac: false,
  playwright: { package: "@playwright/test", version: playwrightVersion },
  accessibility: {
    axeCore: {
      package: "axe-core",
      version: axeVersion,
      scans: completedAxeScans,
      profiles: [
        { id: "wcag-aa", appliesWhen: "cssOff=false", disabledRules: [] },
        {
          id: "css-off-semantic-survival",
          appliesWhen: "cssOff=true",
          disabledRules: ["target-size"],
          rationale: "CSS-off validates semantic survival without author sizing",
        },
      ],
      instrumentation: [
        { id: "page-init-script", appliesWhen: "js=true" },
        {
          id: "serialized-no-js-dom-in-isolated-axe-context",
          appliesWhen: "js=false",
          sourceIdentity: "per-cell SHA-256",
        },
      ],
    },
    contractAudit: { engine: "chromium-aria-plus-census-contract", scans: completedContractScans },
  },
  matrix: {
    scenarios,
    viewports: widths,
    javaScript: [true, false],
    zoom: [100, 200, 400],
    capabilities: ["css-off", "forced-colors", "grayscale", "reduced-motion", "os-dark", "keyboard", "mutations"],
    expectedCells: expectedKeys.size,
    actualCells: cells.length,
    transientNetworkRetries: cells.reduce((total, cell) => total + (cell.navigationRetries || 0), 0),
  },
  failures,
  cells,
};
const target = path.join(root, "results.json");
const temporary = `${target}.tmp-${process.pid}`;
fs.writeFileSync(temporary, `${JSON.stringify(result, null, 2)}\n`);
fs.renameSync(temporary, target);
process.stdout.write(`results.json sha256=${sha256(fs.readFileSync(target))} cells=${cells.length}/${expectedKeys.size}\n`);
if (failures.length) {
  process.stderr.write(`${failures.length} aggregate gate failure(s); see results.json\n`);
  process.exitCode = 1;
}
NODE
then
  gate_rc=1
fi

final_lock="$(sha256sum "${GATE_DIR}/package-lock.json" | cut -d' ' -f1)"
if [[ "${lock_before}" != "${final_lock}" ]]; then
  printf 'Census gate stopped: package-lock.json changed during verification.\n' >&2
  gate_rc=1
fi

if [[ "${gate_rc}" -ne 0 ]]; then
  exit "${gate_rc}"
fi

success=1
