import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

import { expect, test } from "@playwright/test";
import axe from "axe-core";

const BASE = process.env.BASE || "https://127.0.0.1:8443";
const SCENARIO = process.env.CENSUS_SCENARIO;
const ARTIFACT_ROOT = process.env.GATE_ARTIFACTS;
const AXE_VERSION = "4.12.1";
const require = createRequire(import.meta.url);
const AXE_SCRIPT_PATH = require.resolve("axe-core/axe.min.js");

if (axe.version !== AXE_VERSION) {
  throw new Error(`Expected axe-core ${AXE_VERSION}, loaded ${axe.version}`);
}

if (!SCENARIO || !ARTIFACT_ROOT) {
  throw new Error("CENSUS_SCENARIO and GATE_ARTIFACTS are required");
}

const SYNTHETIC_HEADERS = {
  "x-auth-subject": "fixture-viewer",
  "x-auth-email": "viewer@example.invalid",
  "x-auth-scope": "fixture",
};

const TEMPLATE_MARKER_CORPUS = "{{CSS}} {{TOPBAR}} {{BANNER}} {{BOUNDARY}} {{LEGEND}} {{QUERY}} {{DEPARTMENT_OPTIONS}} {{GROUP_OPTIONS}} {{COUNT}} {{ROWS}} {{GROUPS}} {{ORG_CHART}} {{NAME_TEXT}} {{AVATAR}} {{NAME}} {{TITLE_LINE}} {{EMAIL_LINE}} {{UPDATED}} {{PROVENANCE}} {{DETAILS}} {{REPORTS}} {{BIO}} {{EDIT}} {{CREATE_FORM}} {{CSRF}} {{CARDS}} {{MEMBER_FORM}} {{CHILD_FORM}} {{GROUP_ID}} {{DESCRIPTION}} {{CREATED}} {{DIRECT_COUNT}} {{RESOLVED_COUNT}} {{DIRECT_MEMBERS}} {{RESOLVED_MEMBERS}} {{CHILD_GROUPS}} {{PARENT_GROUPS}} {{PERSON_OPTIONS}} {{CHILD_GROUP_OPTIONS}}";
const HOSTILE_DEPARTMENT = `研🧭e\u0301究部門<&>-Δ🌐 ${"界".repeat(120)}`;

const FORBIDDEN_COPY = [
  /\bNo people found\b/i,
  /\bcompleteness not verified\b/i,
  /\bMembership changes are audited\b/i,
  /\bverified\b/i,
  /\bapproved\b/i,
  /\bseniority\b/i,
  /\bonline\b/i,
  /\bowner\b/i,
  /\bsteward\b/i,
  /\bmaybe\b/i,
  /\b\d[\d,]*\+(?!\w)/,
  /~/,
];

const PLACEHOLDER_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M/wHwAE/wJ/lQegWAAAAABJRU5ErkJggg==",
  "base64",
);

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function atomicWrite(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, data);
  fs.renameSync(temporary, file);
}

function artifactRecord(root, file, data) {
  const absolute = path.join(root, file);
  atomicWrite(absolute, data);
  return { path: file, sha256: sha256(data) };
}

function modesFor(width) {
  const modes = [];
  for (const js of [true, false]) {
    const suffix = js ? "js" : "nojs";
    modes.push({ id: `baseline-${suffix}`, js, zoom: 100 });
    modes.push({ id: `css-off-${suffix}`, js, zoom: 100, cssOff: true });
    modes.push({ id: `forced-colors-${suffix}`, js, zoom: 100, forcedColors: true });
    modes.push({ id: `grayscale-${suffix}`, js, zoom: 100, grayscale: true });
    modes.push({ id: `reduced-motion-${suffix}`, js, zoom: 100, reducedMotion: true });
    modes.push({ id: `os-dark-${suffix}`, js, zoom: 100, osDark: true });
    // WCAG reflow zoom is measured from the 1440 CSS-pixel desktop surface: 720px at 200%
    // and 360px at 400%. Applying 400% again to the 320px probe would test an artificial 80px.
    if (width === 1440) {
      modes.push({ id: `zoom-200-${suffix}`, js, zoom: 200 });
      modes.push({ id: `zoom-400-${suffix}`, js, zoom: 400 });
    }
  }
  return modes;
}

function effectiveViewport(width, zoom) {
  const effectiveWidth = zoom === 100 ? width : Math.floor(1440 / (zoom / 100));
  return {
    width: effectiveWidth,
    height: effectiveWidth <= 390 ? 844 : 900,
  };
}

function safeHeaders(response) {
  if (!response) return {};
  const headers = response.headers();
  const allow = ["cache-control", "content-type", "location", "vary", "www-authenticate"];
  return Object.fromEntries(allow.filter((name) => headers[name] !== undefined).map((name) => [name, headers[name]]));
}

// Extract maximal phone-like candidates without a lookahead, then enforce the
// token boundary and digit count in code. This prevents regexp backtracking
// from accepting the first 15 digits of a longer identifier. Sources remain
// separate, and horizontal Unicode spaces are supported without allowing a
// gate-inserted newline to join two values.
const PHONE_CANDIDATE_PATTERN = /\+?\d[\d\t\p{Zs}().\/-]*/gu;
const IDENTIFIER_CHAR = /[\p{L}\p{N}_-]/u;

function isPlausiblePhoneCandidate(candidate) {
  const digits = candidate.replace(/\D/g, "");
  if (digits.length < 9 || digits.length > 15 || !/[1-9]/.test(digits)) return false;

  const token = candidate.trim();
  const ipv4 = token.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (ipv4
    && ipv4.slice(1, 5).every((octet) => Number(octet) <= 255)
    && (ipv4[5] === undefined || Number(ipv4[5]) <= 32)) return false;
  if (/^\d{4}[./-]\d{1,2}[./-]\d{1,2}(?:[\t\p{Zs}]+\d{1,6})?$/u.test(token)) return false;
  return true;
}

function containsPhone(textSources) {
  for (const source of textSources) {
    for (const match of source.matchAll(PHONE_CANDIDATE_PATTERN)) {
      const candidate = match[0].replace(/[\t\p{Zs}().\/-]+$/u, "");
      if (!candidate) continue;
      const start = match.index;
      const end = start + candidate.length;
      if (start > 0 && IDENTIFIER_CHAR.test(source[start - 1])) continue;
      if (end < source.length && IDENTIFIER_CHAR.test(source[end])) continue;
      if (isPlausiblePhoneCandidate(candidate)) return true;
    }
  }
  return false;
}

function scanForSecrets(textSources) {
  const findings = [];
  if (textSources.some((value) => typeof value !== "string")) {
    throw new TypeError("secret scan accepts text sources only");
  }
  const text = textSources.join("\n");
  const rules = [
    ["authorization", /\bBearer\s+[A-Za-z0-9._~+/=-]+/i],
    ["csrf-cookie", /__Host-csrf\s*=/i],
    ["csrf-field", /csrf_token\s*[=:]\s*["']?[A-Za-z0-9_-]{8,}/i],
    ["gateway-header", /x-auth-(?:subject|email|scope)\s*[=:]/i],
    ["driver-detail", /\b(?:sqlx|tokio-postgres|postgres(?:ql)?\s+(?:driver|error))\b/i],
    ["secret-url", /[?&](?:access[_-]?token|api[_-]?key|secret|password|credential)=[^&#\s]+/i],
  ];
  for (const [name, rule] of rules) {
    if (rule.test(text)) findings.push(name);
  }
  if (containsPhone(textSources)) findings.push("phone");

  for (const match of text.matchAll(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/gi)) {
    if (!match[1].toLowerCase().endsWith("example.invalid")) findings.push("non-synthetic-email");
  }
  return [...new Set(findings)];
}

const MAX_NETWORK_CHANGE_RETRIES = 2;

function isRetryableNavigationError(error) {
  return error instanceof Error && /\bnet::ERR_NETWORK_CHANGED\b/.test(error.message);
}

async function navigateMatrixPage(context, url) {
  for (let attempt = 0; attempt <= MAX_NETWORK_CHANGE_RETRIES; attempt += 1) {
    const consoleErrors = [];
    const pageErrors = [];
    const failedRequests = [];
    const candidate = await context.newPage();
    candidate.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    candidate.on("pageerror", (error) => pageErrors.push(error.message));
    candidate.on("requestfailed", (request) => failedRequests.push(`${request.method()} ${new URL(request.url()).pathname}`));

    try {
      const response = await candidate.goto(url, { waitUntil: "domcontentloaded" });
      return { page: candidate, response, consoleErrors, pageErrors, failedRequests, retries: attempt };
    } catch (error) {
      const retry = isRetryableNavigationError(error) && attempt < MAX_NETWORK_CHANGE_RETRIES;
      try {
        await candidate.close();
      } catch (closeError) {
        const targetClosed = typeof candidate.isClosed === "function" && candidate.isClosed();
        if (!targetClosed) {
          throw new AggregateError([error, closeError], "failed navigation target remained open after cleanup");
        }
      }
      if (!retry) throw error;
      await new Promise((resolve) => setTimeout(resolve, 100 * (attempt + 1)));
    }
  }
  throw new Error("unreachable navigation retry state");
}

async function contractA11yAudit(page) {
  return page.evaluate(() => {
    const violations = [];
    const visible = (element) => {
      const style = getComputedStyle(element);
      const box = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && box.width > 0 && box.height > 0;
    };
    const accessibleName = (element) => {
      const labelledBy = element.getAttribute("aria-labelledby");
      if (labelledBy) {
        const value = labelledBy
          .split(/\s+/)
          .map((id) => document.getElementById(id)?.textContent?.trim() || "")
          .join(" ")
          .trim();
        if (value) return value;
      }
      const aria = element.getAttribute("aria-label")?.trim();
      if (aria) return aria;
      const id = element.id;
      if (id) {
        const explicit = document.querySelector(`label[for="${CSS.escape(id)}"]`);
        if (explicit?.textContent?.trim()) return explicit.textContent.trim();
      }
      const wrapped = element.closest("label")?.textContent?.trim();
      if (wrapped) return wrapped;
      return element.textContent?.trim() || element.getAttribute("alt")?.trim() || "";
    };

    const ids = new Set();
    for (const element of document.querySelectorAll("[id]")) {
      if (ids.has(element.id)) violations.push(`duplicate-id:${element.id}`);
      ids.add(element.id);
    }
    if (document.querySelectorAll("h1").length !== 1) violations.push("page-must-have-exactly-one-h1");
    if (!document.querySelector("main#main[tabindex=\"-1\"]")) violations.push("missing-focusable-main-landmark");
    if (!document.querySelector("header.topbar")) violations.push("missing-banner-header");
    if (!document.querySelector("nav")) violations.push("missing-navigation-landmark");

    for (const element of document.querySelectorAll("input, select, textarea, button, a[href], [role=region], [role=search]")) {
      if (visible(element) && !accessibleName(element)) {
        violations.push(`missing-accessible-name:${element.tagName.toLowerCase()}`);
      }
    }
    for (const image of document.querySelectorAll("img")) {
      if (!image.hasAttribute("alt")) violations.push("image-missing-alt");
    }
    for (const section of document.querySelectorAll("section[aria-labelledby]")) {
      for (const id of section.getAttribute("aria-labelledby").split(/\s+/)) {
        if (!document.getElementById(id)) violations.push(`broken-aria-labelledby:${id}`);
      }
    }
    for (const list of document.querySelectorAll("ul, ol")) {
      for (const child of list.children) {
        if (child.tagName !== "LI") violations.push(`invalid-list-child:${child.tagName.toLowerCase()}`);
      }
    }

    const parseColor = (raw) => {
      const match = raw.match(/rgba?\((\d+(?:\.\d+)?)[, ]+(\d+(?:\.\d+)?)[, ]+(\d+(?:\.\d+)?)(?:\s*[,/]\s*(\d+(?:\.\d+)?))?\)/);
      return match ? [Number(match[1]), Number(match[2]), Number(match[3]), match[4] === undefined ? 1 : Number(match[4])] : null;
    };
    const background = (element) => {
      let cursor = element;
      while (cursor) {
        const parsed = parseColor(getComputedStyle(cursor).backgroundColor);
        if (parsed && parsed[3] > 0.98) return parsed;
        cursor = cursor.parentElement;
      }
      return [255, 255, 255, 1];
    };
    const channel = (value) => {
      const v = value / 255;
      return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
    };
    const luminance = (rgb) => 0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1]) + 0.0722 * channel(rgb[2]);
    const ratio = (a, b) => {
      const high = Math.max(luminance(a), luminance(b));
      const low = Math.min(luminance(a), luminance(b));
      return (high + 0.05) / (low + 0.05);
    };
    const seenStyles = new Set();
    const contrastCandidates = document.querySelectorAll(
      "h1,h2,h3,p,a,button,label,input,select,.prov,.banner,.bound,.section-note,.readonly-note,.roll__name,.roll__title,.member__name",
    );
    for (const element of contrastCandidates) {
      if (!visible(element) || !(element.textContent || element.value || element.placeholder)?.trim()) continue;
      const style = getComputedStyle(element);
      const fg = parseColor(style.color);
      const bg = background(element);
      if (!fg || fg[3] < 0.98) continue;
      const signature = `${style.color}|${bg.slice(0, 3).join(",")}|${style.fontSize}|${style.fontWeight}`;
      if (seenStyles.has(signature)) continue;
      seenStyles.add(signature);
      const size = Number.parseFloat(style.fontSize);
      const weight = Number.parseInt(style.fontWeight, 10) || 400;
      const threshold = size >= 24 || (size >= 18.66 && weight >= 700) ? 3 : 4.5;
      if (ratio(fg, bg) + 0.01 < threshold) violations.push(`contrast:${signature}`);
    }
    return [...new Set(violations)].sort();
  });
}

async function axeA11yAudit(browser, page, mode, effectiveViewport) {
  let auditContext = null;
  let auditPage = page;
  let instrumentation = "page-init-script";
  let sourceHtmlSha256 = null;

  if (!mode.js) {
    const sourceHtml = await page.content();
    sourceHtmlSha256 = sha256(sourceHtml);
    instrumentation = "serialized-no-js-dom-in-isolated-axe-context";
    auditContext = await browser.newContext({
      ignoreHTTPSErrors: true,
      javaScriptEnabled: true,
      viewport: effectiveViewport,
      screen: effectiveViewport,
      colorScheme: mode.osDark ? "dark" : "light",
      reducedMotion: mode.reducedMotion ? "reduce" : "no-preference",
      forcedColors: mode.forcedColors ? "active" : "none",
    });
    auditPage = await auditContext.newPage();
    await auditPage.setContent(sourceHtml, { waitUntil: "domcontentloaded" });
    if (mode.grayscale) {
      await auditPage.addStyleTag({ content: ":root { filter: grayscale(1) !important; }" });
    }
    await auditPage.addScriptTag({ path: AXE_SCRIPT_PATH });
  }

  try {
    return await auditPage.evaluate(async ({ expectedVersion, cssOff, instrumentation, sourceHtmlSha256 }) => {
      if (!globalThis.axe || globalThis.axe.version !== expectedVersion) {
        throw new Error(`axe-core injection mismatch: ${globalThis.axe?.version ?? "missing"}`);
      }
      const disabledRules = [];
      if (cssOff) disabledRules.push("target-size");
      const result = await globalThis.axe.run(document, {
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"],
        },
        resultTypes: ["violations"],
        rules: Object.fromEntries(disabledRules.map((id) => [id, { enabled: false }])),
      });
      return {
        version: globalThis.axe.version,
        runProfile: {
          standard: "WCAG 2.x A/AA",
          instrumentation,
          sourceHtmlSha256,
          disabledRules,
          rationale: {
            "target-size": "CSS-off validates semantic survival without author sizing",
          },
        },
        violations: result.violations.map((violation) => ({
          id: violation.id,
          impact: violation.impact,
          help: violation.help,
          nodes: violation.nodes.map((node) => ({
            target: node.target,
            failureSummary: node.failureSummary,
          })),
        })),
      };
    }, {
      expectedVersion: AXE_VERSION,
      cssOff: Boolean(mode.cssOff),
      instrumentation,
      sourceHtmlSha256,
    });
  } finally {
    if (auditContext) await auditContext.close();
  }
}

async function keyboardAudit(page) {
  const failures = [];
  await page.evaluate(() => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
  });
  await page.keyboard.press("Tab");
  const first = await page.evaluate(() => ({
    className: document.activeElement?.className || "",
    href: document.activeElement?.getAttribute("href") || "",
    focusVisible: document.activeElement?.matches(":focus-visible") || false,
  }));
  if (!String(first.className).split(/\s+/).includes("skip-link")) failures.push("skip-link-is-not-first-tab-stop");
  if (!first.focusVisible) failures.push("skip-link-has-no-focus-visible-state");
  await page.keyboard.press("Enter");
  await page.waitForURL((url) => url.hash === "#main", { timeout: 2_000 }).catch(() => {});
  await page.waitForTimeout(25);
  const skipTarget = await page.evaluate(() => document.activeElement?.id === "main" || location.hash === "#main");
  if (!skipTarget) failures.push("skip-link-does-not-target-main");

  await page.keyboard.press("Tab");
  const next = await page.evaluate(() => {
    const active = document.activeElement;
    if (!active || active === document.body) return { ok: false, tag: "body" };
    const style = getComputedStyle(active);
    const visibleCue = style.outlineStyle !== "none" || style.boxShadow !== "none" || style.borderStyle !== "none";
    return { ok: active.matches(":focus-visible") && visibleCue, tag: active.tagName.toLowerCase() };
  });
  if (!next.ok) failures.push(`next-control-has-no-visible-keyboard-focus:${next.tag}`);
  return failures;
}

async function pageContract(page, scenario, mode) {
  const failures = [];
  const add = (condition, message) => {
    if (!condition) failures.push(message);
  };
  const bodyText = await page.locator("body").innerText();
  const normalized = bodyText.replace(/\s+/g, " ").trim();

  add((await page.locator("script").count()) === 0, "Census must remain script-free");
  add((await page.locator("h1").count()) === 1, "page must have one h1");
  add((await page.locator("a.skip-link[href='#main']").count()) === 1, "missing unique skip link");
  add((await page.locator("main#main[tabindex='-1']").count()) === 1, "missing focus target main");
  add((await page.locator("meta[name='color-scheme'][content='light']").count()) === 1, "light-only color-scheme marker drifted");
  add((await page.locator("[onerror]").count()) === 0, "inline onerror is forbidden");
  add((await page.locator("[href^='javascript:'],[src^='javascript:']").count()) === 0, "javascript URL survived sanitization");

  for (const pattern of FORBIDDEN_COPY) {
    add(!pattern.test(normalized), `forbidden copy matched ${pattern}`);
  }

  const pageOverflow = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
    overflowingCells: [...document.querySelectorAll(".roll__row > *, .member > *, [class*='__cell']")]
      .filter((element) => element.scrollWidth > element.clientWidth + 1).length,
    orgRegions: [...document.querySelectorAll(".org-chart")].map((element) => ({
      tabindex: element.getAttribute("tabindex"),
      role: element.getAttribute("role"),
      label: element.getAttribute("aria-label"),
      overflowX: getComputedStyle(element).overflowX,
    })),
  }));
  add(pageOverflow.scrollWidth <= pageOverflow.clientWidth + 1, `page overflows ${pageOverflow.scrollWidth}/${pageOverflow.clientWidth}`);
  add(pageOverflow.overflowingCells === 0, `${pageOverflow.overflowingCells} data cells overflow`);
  for (const region of pageOverflow.orgRegions) {
    add(region.tabindex === "0" && region.role === "region" && Boolean(region.label), "org chart lacks keyboard region contract");
    if (!mode.cssOff) add(["auto", "scroll"].includes(region.overflowX), "org chart is not the intentional horizontal-scroll owner");
  }

  const provenance = await page.locator(".prov").evaluateAll((elements) => elements.map((element) => {
    const legendItem = element.closest(".legend__item");
    const hiddenLegendSwatch = Boolean(legendItem) && element.getAttribute("aria-hidden") === "true";
    return {
      hiddenLegendSwatch,
      text: element.textContent?.trim() || "",
      legendWord: hiddenLegendSwatch
        ? legendItem.querySelector(".legend__word")?.textContent?.trim() || ""
        : "",
      borderStyle: getComputedStyle(element).borderStyle,
    };
  }));
  for (const mark of provenance) {
    if (mark.hiddenLegendSwatch) {
      add(Boolean(mark.legendWord), "decorative provenance legend swatch has no associated word label");
    } else {
      add(Boolean(mark.text), "provenance mark has no self-contained word label");
    }
    if (!mode.cssOff) add(!["none", "hidden"].includes(mark.borderStyle), "provenance mark has no border shape");
  }

  const landmarkFailures = await page.evaluate(() => [...document.querySelectorAll("section")].filter((section) => {
    const directLabel = section.getAttribute("aria-label")?.trim();
    if (directLabel) return false;
    const labelledBy = section.getAttribute("aria-labelledby");
    return !labelledBy || !labelledBy.split(/\s+/).every((id) => {
      const label = document.getElementById(id);
      return label && /^H[2-6]$/.test(label.tagName);
    });
  }).length);
  add(landmarkFailures === 0, `${landmarkFailures} sections lack an accessible label or labelled heading`);
  add((await page.locator(".banner:not([role='status'])").count()) === 0, "banner is not a status live region");
  add((await page.locator(".bound:not([role='note']),.prov-note:not([role='note'])").count()) === 0, "truth note lacks role=note");

  if (mode.reducedMotion) {
    const moving = await page.evaluate(() => [...document.querySelectorAll("*")].filter((element) => {
      const style = getComputedStyle(element);
      const durations = `${style.animationDuration},${style.transitionDuration}`
        .split(",")
        .map((part) => part.trim())
        .filter(Boolean)
        .map((part) => part.endsWith("ms") ? Number.parseFloat(part) / 1000 : Number.parseFloat(part));
      return durations.some((duration) => Number.isFinite(duration) && duration > 0.02);
    }).length);
    add(moving === 0, `${moving} elements retain motion over 20ms`);
  }

  if (mode.osDark) {
    const scheme = await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme);
    add(scheme.split(/\s+/).includes("light"), `OS-dark changed the light material (${scheme})`);
    add((await page.locator("[data-theme]").count()) === 0, "Census stamped a theme override");
  }

  switch (scenario) {
    case "populated":
      add((await page.locator(".roll__row").count()) > 0, "populated fixture has no roll rows");
      break;
    case "empty":
      add(normalized.includes("0 people enumerated by the identity source"), "empty identity truth copy missing");
      add(normalized.includes("No one else is on the roll yet"), "empty roll exception copy missing");
      add((await page.locator(".prov--provisional").count()) > 0, "provisional viewer is not marked");
      break;
    case "no-results":
      add((await page.locator(".roll__empty").count()) === 1, "no-results fixture lacks the list-valid empty row");
      add(normalized.includes("No matches"), "no-results copy drifted");
      break;
    case "identity-unavailable":
      add(normalized.includes("Identity source unavailable"), "identity outage banner missing");
      add((await page.locator(".roll__row").count()) === 0, "identity outage rendered a fabricated row");
      add(!normalized.includes("1 person"), "identity outage rendered a healthy count");
      break;
    case "profile-unavailable":
      add(normalized.includes("Profiles unavailable"), "profile outage note missing");
      add((await page.locator(".roll__row").count()) > 0, "profile outage withheld proven identities");
      break;
    case "group-unavailable":
      add(normalized.includes("Groups unavailable"), "group outage note missing");
      break;
    case "both-unavailable":
      add(normalized.includes("Directory sources unavailable"), "combined outage banner missing");
      add((await page.locator(".roll__row").count()) === 0, "combined outage rendered a fabricated row");
      break;
    case "n1999":
      add(normalized.includes("1,999 people on the roll"), "1,999 exact bound copy missing");
      add((await page.locator(".bound").count()) === 0, "1,999 incorrectly rendered overflow boundary");
      break;
    case "n2000":
      add(normalized.includes("2,000 people on the roll"), "2,000 exact bound copy missing");
      add((await page.locator(".bound").count()) === 0, "exact 2,000 incorrectly rendered overflow boundary");
      break;
    case "n2001":
      add(normalized.includes("Showing the first 2,000 people"), "2,001 overflow headline missing");
      add(normalized.includes("More people exist than shown — the roll stops at a survey bound of 2,000."), "overflow boundary note missing");
      break;
    case "hostile-data":
      add((await page.locator("img:not([referrerpolicy='no-referrer'])").count()) === 0, "avatar referrer policy drifted");
      add((await page.locator("body").innerHTML()).includes("&lt;script&gt;") || !normalized.includes("script"), "hostile bio was not escaped or sanitized");
      break;
    case "missing-identity":
      add((await page.locator(".readonly-note").count()) > 0, "missing identity lacks read-only disclosure");
      add((await page.locator("form[action^='/api/']").count()) === 0, "missing identity retained a mutation form");
      break;
  }

  return { failures, pageOverflow };
}

async function submitAndCapture(page, form) {
  const action = new URL(await form.getAttribute("action"), page.url()).href;
  const submit = form.locator("button[type='submit']");
  await submit.waitFor({ state: "visible" });
  await submit.evaluate((element) => element.scrollIntoView({ block: "center", inline: "nearest" }));
  // Chromium can finish DOMContentLoaded before its no-JS navigation updates the
  // compositor hit-test tree. Require three identical geometry samples whose
  // centre point resolves to the control, proving stable pointer actionability
  // without force-clicking through an overlay.
  let previousBox = "";
  let stableSamples = 0;
  await expect.poll(
    () => submit.evaluate((element) => {
      const rect = element.getBoundingClientRect();
      const hit = document.elementFromPoint(
        rect.left + rect.width / 2,
        rect.top + rect.height / 2,
      );
      return {
        box: [rect.left, rect.top, rect.width, rect.height]
          .map((value) => value.toFixed(2))
          .join(":"),
        nonzero: rect.width > 0 && rect.height > 0,
        ownsCenter: hit === element || Boolean(hit && element.contains(hit)),
      };
    }).then(({ box, nonzero, ownsCenter }) => {
      if (!nonzero || !ownsCenter) {
        previousBox = "";
        stableSamples = 0;
        return false;
      }
      stableSamples = box === previousBox ? stableSamples + 1 : 1;
      previousBox = box;
      return stableSamples >= 3;
    }),
    { timeout: 5_000, intervals: [50, 100, 150, 250] },
  ).toBe(true);
  await submit.focus();
  await expect(submit).toBeFocused();
  // Keep pointer actionability as a gate above, then activate the same native
  // control through its keyboard contract. This avoids a Chromium no-JS
  // compositor race without using requestSubmit(), dispatchEvent(), or force.
  const [request] = await Promise.all([
    page.waitForRequest(
      (candidate) => candidate.url() === action && candidate.method() === "POST",
    ),
    page.waitForNavigation({ waitUntil: "domcontentloaded" }),
    submit.press("Enter"),
  ]);
  const response = await request.response();
  // Settle a 303 redirect or an in-place 4xx document before the next native
  // form lookup; otherwise an immediately following goto can race the old page.
  await page.waitForLoadState("networkidle");
  if (!response) throw new Error(`native POST returned no response: ${action}`);
  return response;
}

async function createGroup(page, name) {
  await page.goto(`${BASE}/groups`, { waitUntil: "domcontentloaded" });
  const form = page.locator("form[action='/api/groups']").first();
  await form.locator("input[name='name']").fill(name);
  const description = form.locator("input[name='description'],textarea[name='description']");
  if (await description.count()) await description.fill("Synthetic browser-gate group");
  const response = await submitAndCapture(page, form);
  if (response.status() !== 303) throw new Error(`create group ended at ${response.status()}`);
  await page.goto(`${BASE}/groups`, { waitUntil: "domcontentloaded" });
  const label = page.locator(".group__name a").and(page.getByRole("link", { name, exact: true })).first();
  const href = await label.getAttribute("href") || "";
  if (!href.startsWith("/groups/")) throw new Error(`created group link missing for ${name}`);
  return href;
}

async function mutationAudit(browser, js) {
  const failures = [];
  const events = {};
  const context = await browser.newContext({
    baseURL: BASE,
    ignoreHTTPSErrors: true,
    javaScriptEnabled: js,
    viewport: { width: 390, height: 844 },
    extraHTTPHeaders: SYNTHETIC_HEADERS,
  });
  const page = await context.newPage();
  const suffix = js ? "js" : "nojs";
  try {
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
    const selfLink = page.locator(".roll__row:has(.roll__you) a[href^='/u/'], a[href^='/u/']:has(.roll__you)").first();
    if (await selfLink.count()) {
      await selfLink.click();
      await page.waitForLoadState("domcontentloaded");
      const profile = page.locator("form[action='/api/profile']").first();
      if (await profile.count()) {
        const displayName = profile.locator("input[name='display_name']");
        if (await displayName.count()) await displayName.fill(`Fixture Viewer ${suffix}`);
        const response = await submitAndCapture(page, profile);
        events.profileEdit = response.status();
        if (response.status() !== 303) failures.push(`profile edit status ${response.status()}`);
      } else {
        failures.push("profile edit form missing for synthetic viewer");
      }
    } else {
      failures.push("synthetic viewer link missing");
    }

    const parentName = `Gate Parent 390 ${suffix}`;
    const childName = `Gate Child 390 ${suffix}`;
    const parentHref = await createGroup(page, parentName);
    const childHref = await createGroup(page, childName);
    events.groupCreate = 303;

    await page.goto(`${BASE}${parentHref}`, { waitUntil: "domcontentloaded" });
    const memberForm = page.locator(`form[action='${parentHref}/members'], form[action='/api${parentHref}/members']`).first();
    if (await memberForm.count()) {
      const memberSelect = memberForm.locator("select[name='sub']");
      const memberValue = await memberSelect.locator("option:not([value=''])").first().getAttribute("value");
      if (memberValue) {
        await memberSelect.selectOption(memberValue);
        const memberResponse = await submitAndCapture(page, memberForm);
        events.memberAdd = memberResponse.status();
        if (memberResponse.status() !== 303) failures.push(`member add status ${memberResponse.status()}`);
        await page.goto(`${BASE}${parentHref}`, { waitUntil: "domcontentloaded" });
        const removeMember = page.locator(`form[action='${parentHref}/members']:has(input[name='action'][value='remove']), form[action='/api${parentHref}/members']:has(input[name='action'][value='remove'])`).first();
        if (await removeMember.count()) {
          const removeResponse = await submitAndCapture(page, removeMember);
          events.memberRemove = removeResponse.status();
          if (removeResponse.status() !== 303) failures.push(`member remove status ${removeResponse.status()}`);
        } else failures.push("member remove form missing after add");
      } else failures.push("member select has no synthetic option");
    } else failures.push("member add form missing");

    await page.goto(`${BASE}${parentHref}`, { waitUntil: "domcontentloaded" });
    const childForm = page.locator(`form[action='${parentHref}/children'], form[action='/api${parentHref}/children']`).first();
    if (await childForm.count()) {
      await childForm.locator("select[name='child_group_id']").selectOption(childHref.split("/").pop());
      const childResponse = await submitAndCapture(page, childForm);
      events.childAdd = childResponse.status();
      if (childResponse.status() !== 303) failures.push(`child add status ${childResponse.status()}`);
    } else failures.push("child add form missing");

    await page.goto(`${BASE}${childHref}`, { waitUntil: "domcontentloaded" });
    const cycleForm = page.locator(`form[action='${childHref}/children'], form[action='/api${childHref}/children']`).first();
    if (await cycleForm.count()) {
      await cycleForm.locator("select[name='child_group_id']").selectOption(parentHref.split("/").pop());
      const cycleResponse = await submitAndCapture(page, cycleForm);
      events.cycle = cycleResponse.status();
      if (cycleResponse.status() !== 400) failures.push(`cycle expected 400, received ${cycleResponse.status()}`);
    } else failures.push("cycle form missing");

    await page.goto(`${BASE}${parentHref}`, { waitUntil: "domcontentloaded" });
    const removeChild = page.locator(`form[action='${parentHref}/children']:has(input[name='action'][value='remove']), form[action='/api${parentHref}/children']:has(input[name='action'][value='remove'])`).first();
    if (await removeChild.count()) {
      const removeResponse = await submitAndCapture(page, removeChild);
      events.childRemove = removeResponse.status();
      if (removeResponse.status() !== 303) failures.push(`child remove status ${removeResponse.status()}`);
    } else failures.push("child remove form missing after add");

    await page.goto(`${BASE}/groups`, { waitUntil: "domcontentloaded" });
    const conflict = page.locator("form[action='/api/groups']").first();
    await conflict.locator("input[name='name']").fill(parentName);
    const conflictResponse = await submitAndCapture(page, conflict);
    events.conflict = conflictResponse.status();
    if (conflictResponse.status() !== 409) failures.push(`conflict expected 409, received ${conflictResponse.status()}`);

    await page.goto(`${BASE}/groups`, { waitUntil: "domcontentloaded" });
    const csrfResponse = await context.request.post(`${BASE}/api/groups`, {
      form: { name: `Bad CSRF ${suffix}`, description: "synthetic", csrf_token: "definitely-wrong" },
      maxRedirects: 0,
    });
    events.csrf = csrfResponse.status();
    if (csrfResponse.status() !== 401) failures.push(`bad CSRF expected 401, received ${csrfResponse.status()}`);
  } catch (error) {
    failures.push(`mutation exception: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    await context.close();
  }
  return { failures, events };
}

test("secret scanner separates bounded phone tokens from evidence metadata", () => {
  const negatives = [
    ["sourceHtmlSha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
    ["sourceHtmlSha256=abcdef858432118babcdef0123456789abcdef0123456789abcdef0123456789"],
    ["sourceHtmlSha256=abcdef0123456789abcdef0123456789abcdef0123456789abcdef123456789"],
    ["short: 12345678"],
    ["long: 1234567890123456"],
    ["long-separated: 1-2-3-4-5-6-7-8-9-0-1-2-3-4-5-6"],
    ["long-suffixed: 1-2-3-4-5-6-7-8-9-0-1-2-3-4-5-6x"],
    ["long-space-prefix: 1 234567890123456"],
    ["long-international-groups: +49 30 123456789012"],
    ["id_123456789_xyz"],
    ["id-123456789-x"],
    ["unicode-id: 用户123456789姓名"],
    ["ipv4: 192.168.100.100"],
    ["cidr: 192.168.100.100/24"],
    ["date-like: 2026.08.04 1"],
    ["compact-datetime: 2026.08.04 123456"],
    ["zeroes: 000000000"],
    ["split: 12345", "6789"],
  ];
  for (const sources of negatives) expect(scanForSecrets(sources), sources.join(" | ")).not.toContain("phone");

  const positives = [
    ["minimum: 123456789"],
    ["maximum: 123456789012345"],
    ["formatted: +49 (30) 123-456.789"],
    ["national: 0301234567"],
    ["international-prefix: 0049123456789"],
    ["same-source pair with explicit boundary: 123456789, 987654321"],
    ["nbsp: +49\u00a030\u00a01234\u00a05678"],
    ["narrow-nbsp: +49\u202f30\u202f1234\u202f5678"],
    ["slash: 030/1234567"],
  ];
  for (const sources of positives) expect(scanForSecrets(sources), sources.join(" | ")).toContain("phone");
  expect(scanForSecrets(positives[2])).toContain("phone");
  expect(scanForSecrets(positives[2])).toContain("phone");
});

test("navigation retry policy is narrow and bounded", () => {
  expect(isRetryableNavigationError(new Error("page.goto: net::ERR_NETWORK_CHANGED"))).toBe(true);
  expect(isRetryableNavigationError(new Error("page.goto: net::ERR_NETWORK_CHANGED_BY_POLICY"))).toBe(false);
  expect(isRetryableNavigationError(new Error("page.goto: net::ERR_CONNECTION_REFUSED"))).toBe(false);
  expect(isRetryableNavigationError(new Error("page.goto: Timeout 10000ms exceeded"))).toBe(false);
  expect(isRetryableNavigationError("net::ERR_NETWORK_CHANGED")).toBe(false);
  expect(MAX_NETWORK_CHANGE_RETRIES).toBe(2);
});

test("network-change retry uses a fresh page and isolates attempt diagnostics", async () => {
  const attempts = [];
  const context = {
    async newPage() {
      const attempt = attempts.length;
      const listeners = new Map();
      const candidate = {
        closed: false,
        on(event, listener) { listeners.set(event, listener); },
        isClosed() { return this.closed; },
        async goto() {
          if (attempt === 0) {
            listeners.get("console")?.({ type: () => "error", text: () => "discarded transient console" });
            listeners.get("pageerror")?.(new Error("discarded transient page error"));
            listeners.get("requestfailed")?.({ method: () => "GET", url: () => `${BASE}/` });
            throw new Error("page.goto: net::ERR_NETWORK_CHANGED");
          }
          return { status: () => 200 };
        },
        async close() { this.closed = true; },
      };
      attempts.push(candidate);
      return candidate;
    },
  };

  const navigation = await navigateMatrixPage(context, `${BASE}/`);
  expect(attempts).toHaveLength(2);
  expect(attempts[0].closed).toBe(true);
  expect(navigation.page).toBe(attempts[1]);
  expect(navigation.retries).toBe(1);
  expect(navigation.consoleErrors).toEqual([]);
  expect(navigation.pageErrors).toEqual([]);
  expect(navigation.failedRequests).toEqual([]);
});

test("navigation retry exhausts exactly and cleanup failures fail closed", async () => {
  const attempts = [];
  const exhaustedContext = {
    async newPage() {
      const candidate = {
        closed: false,
        on() {},
        isClosed() { return this.closed; },
        async goto() { throw new Error("page.goto: net::ERR_NETWORK_CHANGED"); },
        async close() { this.closed = true; },
      };
      attempts.push(candidate);
      return candidate;
    },
  };
  await expect(navigateMatrixPage(exhaustedContext, `${BASE}/`)).rejects.toThrow("net::ERR_NETWORK_CHANGED");
  expect(attempts).toHaveLength(3);
  expect(attempts.every((candidate) => candidate.closed)).toBe(true);

  let nonRetryAttempts = 0;
  const nonRetryContext = {
    async newPage() {
      nonRetryAttempts += 1;
      return {
        closed: false,
        on() {},
        isClosed() { return this.closed; },
        async goto() { throw new Error("page.goto: net::ERR_CONNECTION_REFUSED"); },
        async close() { this.closed = true; },
      };
    },
  };
  await expect(navigateMatrixPage(nonRetryContext, `${BASE}/`)).rejects.toThrow("net::ERR_CONNECTION_REFUSED");
  expect(nonRetryAttempts).toBe(1);

  const leakingContext = {
    async newPage() {
      return {
        on() {},
        isClosed() { return false; },
        async goto() { throw new Error("page.goto: net::ERR_NETWORK_CHANGED"); },
        async close() { throw new Error("target cleanup failed"); },
      };
    },
  };
  await expect(navigateMatrixPage(leakingContext, `${BASE}/`)).rejects.toThrow("target remained open");
});

test("template markers remain opaque across query and dossier surfaces", async ({ browser }, testInfo) => {
  test.skip(SCENARIO !== "hostile-data", "marker corpus is isolated to the hostile-data fixture");
  const width = Number(testInfo.project.metadata.viewportWidth);

  for (const javaScriptEnabled of [true, false]) {
    const context = await browser.newContext({
      baseURL: BASE,
      ignoreHTTPSErrors: true,
      javaScriptEnabled,
      viewport: effectiveViewport(width, 100),
      extraHTTPHeaders: SYNTHETIC_HEADERS,
    });
    const page = await context.newPage();

    try {
      const query = encodeURIComponent(TEMPLATE_MARKER_CORPUS);
      await page.goto(`${BASE}/?q=${query}&dept=${encodeURIComponent(HOSTILE_DEPARTMENT)}`, { waitUntil: "domcontentloaded" });
      expect(await page.locator("#filter-q").inputValue()).toBe(TEMPLATE_MARKER_CORPUS);
      expect(await page.locator("#filter-dept").inputValue()).toBe(HOSTILE_DEPARTMENT);
      expect(await page.locator("header.topbar").count()).toBe(1);
      expect(await page.locator("style").count()).toBe(1);
      expect(await page.locator(".org-chart").count()).toBe(1);
      const hostileGroupOption = page.locator('option[value="fixture-group-hostile"]');
      expect(await hostileGroupOption.count()).toBe(1);
      expect(await hostileGroupOption.getAttribute("aria-label")).toContain(TEMPLATE_MARKER_CORPUS);
      expect(Array.from((await hostileGroupOption.textContent()) ?? "").length).toBeLessThanOrEqual(17);
      const hostileDepartmentOption = await page.locator("#filter-dept option").evaluateAll((options, expected) => {
        const option = options.find((candidate) => candidate.value === expected);
        return option ? {
          value: option.value,
          ariaLabel: option.getAttribute("aria-label"),
          title: option.getAttribute("title"),
          text: option.textContent ?? "",
        } : null;
      }, HOSTILE_DEPARTMENT);
      expect(hostileDepartmentOption).not.toBeNull();
      expect(hostileDepartmentOption.value).toBe(HOSTILE_DEPARTMENT);
      expect(hostileDepartmentOption.ariaLabel).toBe(HOSTILE_DEPARTMENT);
      expect(hostileDepartmentOption.title).toBe(HOSTILE_DEPARTMENT);
      expect(hostileDepartmentOption.text).toBe(`${Array.from(HOSTILE_DEPARTMENT).slice(0, 16).join("")}…`);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
      await page.locator("style").evaluate((node) => node.remove());
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);

      await page.goto(`${BASE}/u/fixture-hostile`, { waitUntil: "domcontentloaded" });
      expect(await page.locator("header.topbar").count()).toBe(1);
      expect(await page.locator("h1.person__name").count()).toBe(1);
      expect(await page.locator("h1.person__name").innerText()).toContain(TEMPLATE_MARKER_CORPUS);
      expect(await page.locator(".prose").innerText()).toContain(TEMPLATE_MARKER_CORPUS);

      await page.goto(`${BASE}/groups/fixture-group-hostile`, { waitUntil: "domcontentloaded" });
      expect(await page.locator("header.topbar").count()).toBe(1);
      expect(await page.locator("h1").count()).toBe(1);
      expect(await page.locator("h1").innerText()).toContain(TEMPLATE_MARKER_CORPUS);
      expect(await page.locator(".group__desc").innerText()).toContain(TEMPLATE_MARKER_CORPUS);
      expect(await page.locator("[onerror]").count()).toBe(0);
    } finally {
      await context.close();
    }
  }
});

test("synthetic scenario × responsive/capability matrix", async ({ browser }, testInfo) => {
  test.setTimeout(900_000);
  const width = Number(testInfo.project.metadata.viewportWidth);
  const cells = [];
  const matrixFailures = [];
  const scenarioRoot = path.join(ARTIFACT_ROOT, SCENARIO);
  fs.mkdirSync(scenarioRoot, { recursive: true });

  for (const mode of modesFor(width)) {
    const effective = effectiveViewport(width, mode.zoom);
    const cellFailures = [];
    let consoleErrors = [];
    let pageErrors = [];
    let failedRequests = [];
    let response;
    let page;
    let context;
    let aria = "";
    let visibleText = "";
    let screenshot = PLACEHOLDER_PNG;
    let overflow = { scrollWidth: 0, clientWidth: 0, overflowingCells: 0, orgRegions: [] };
    let contractA11yViolations = ["contract-audit-not-run"];
    let contractA11yCompleted = false;
    let axeAudit = {
      version: null,
      runProfile: null,
      violations: [{ id: "axe-audit-not-run", impact: null, help: "axe audit did not run", nodes: [] }],
    };
    let axeCompleted = false;
    let mutations = null;
    let navigationRetries = 0;

    try {
      context = await browser.newContext({
        baseURL: BASE,
        ignoreHTTPSErrors: true,
        javaScriptEnabled: mode.js,
        viewport: effective,
        screen: effective,
        colorScheme: mode.osDark ? "dark" : "light",
        reducedMotion: mode.reducedMotion ? "reduce" : "no-preference",
        forcedColors: mode.forcedColors ? "active" : "none",
        extraHTTPHeaders: SCENARIO === "missing-identity" ? {} : SYNTHETIC_HEADERS,
      });
      if (mode.js) await context.addInitScript({ path: AXE_SCRIPT_PATH });
      const route = SCENARIO === "no-results"
        ? "/?q=definitely-no-such-person"
        : SCENARIO === "missing-identity" ? "/groups" : "/";
      const navigation = await navigateMatrixPage(context, `${BASE}${route}`);
      page = navigation.page;
      response = navigation.response;
      consoleErrors = navigation.consoleErrors;
      pageErrors = navigation.pageErrors;
      failedRequests = navigation.failedRequests;
      navigationRetries = navigation.retries;
      if (mode.cssOff) {
        await page.evaluate(() => document.querySelectorAll("style,link[rel='stylesheet']").forEach((element) => element.remove()));
      }
      if (mode.grayscale) {
        // `page.addStyleTag()` never resolves in Chromium contexts with JavaScript disabled.
        // Install the same author rule through CDP so the no-JS grayscale cell stays a real test.
        const cdp = await context.newCDPSession(page);
        await cdp.send("DOM.enable");
        await cdp.send("CSS.enable");
        const { frameTree } = await cdp.send("Page.getFrameTree");
        const { styleSheetId } = await cdp.send("CSS.createStyleSheet", { frameId: frameTree.frame.id });
        await cdp.send("CSS.setStyleSheetText", {
          styleSheetId,
          text: ":root { filter: grayscale(1) !important; }",
        });
      }
      await page.waitForTimeout(30);

      if (!response || response.status() !== 200) cellFailures.push(`root status ${response?.status() ?? "missing"}`);
      if (response?.headers()["cache-control"] !== "private, no-store") cellFailures.push(`cache-control ${response?.headers()["cache-control"] ?? "missing"}`);
      if (response?.headers().vary !== undefined) cellFailures.push(`unexpected Vary ${response.headers().vary}`);

      const contract = await pageContract(page, SCENARIO, mode);
      cellFailures.push(...contract.failures);
      overflow = contract.pageOverflow;
      contractA11yViolations = await contractA11yAudit(page);
      contractA11yCompleted = true;
      cellFailures.push(...contractA11yViolations.map((violation) => `contract-a11y:${violation}`));
      axeAudit = await axeA11yAudit(browser, page, mode, effective);
      axeCompleted = true;
      cellFailures.push(...axeAudit.violations.map((violation) => `axe:${violation.id}:${violation.nodes.length}`));
      cellFailures.push(...await keyboardAudit(page));

      if (SCENARIO === "populated" && width === 390 && mode.id.startsWith("baseline-")) {
        mutations = await mutationAudit(browser, mode.js);
        cellFailures.push(...mutations.failures);
      }

      visibleText = await page.locator("body").innerText();
      aria = await page.locator("body").ariaSnapshot();
      screenshot = await page.screenshot({ fullPage: false, animations: "disabled" });
    } catch (error) {
      cellFailures.push(`cell exception: ${error instanceof Error ? error.message : String(error)}`);
      if (page) {
        try { visibleText = await page.locator("body").innerText(); } catch { visibleText = "Visible text unavailable"; }
        try { aria = await page.locator("body").ariaSnapshot(); } catch { aria = "ARIA snapshot unavailable"; }
        try { screenshot = await page.screenshot({ fullPage: false, animations: "disabled" }); } catch { /* keep placeholder */ }
      }
    }

    cellFailures.push(...consoleErrors.map((message) => `console:${message}`));
    cellFailures.push(...pageErrors.map((message) => `pageerror:${message}`));
    cellFailures.push(...failedRequests.map((message) => `requestfailed:${message}`));

    const prefix = `${SCENARIO}-${width}-${mode.id}`;
    const httpArtifact = {
      syntheticOnly: true,
      hmac: false,
      baseOrigin: "https://127.0.0.1:8443",
      status: response?.status() ?? 0,
      headers: safeHeaders(response),
      effectiveViewport: effective,
      overflow,
      a11yEngine: {
        axeCore: axeAudit.version,
        contract: "chromium-aria-plus-census-contract",
      },
      axeRunProfile: axeAudit.runProfile,
      axeCompleted,
      axeViolations: axeAudit.violations,
      contractA11yCompleted,
      contractA11yViolations,
      mutations: mutations?.events ?? null,
      navigationRetries,
      failures: cellFailures,
    };
    const httpText = `${JSON.stringify(httpArtifact, null, 2)}\n`;
    const leakFindings = scanForSecrets([visibleText, aria, httpText]);
    cellFailures.push(...leakFindings.map((finding) => `pii-or-secret:${finding}`));

    const artifacts = {
      screenshot: artifactRecord(scenarioRoot, `${prefix}.png`, screenshot),
      aria: artifactRecord(scenarioRoot, `${prefix}.aria.yml`, `${aria}\n`),
      http: artifactRecord(scenarioRoot, `${prefix}.http.json`, httpText),
    };
    const cell = {
      scenario: SCENARIO,
      viewport: width,
      js: mode.js,
      zoom: mode.zoom,
      forcedColors: Boolean(mode.forcedColors),
      grayscale: Boolean(mode.grayscale),
      reducedMotion: Boolean(mode.reducedMotion),
      osDark: Boolean(mode.osDark),
      cssOff: Boolean(mode.cssOff),
      httpStatus: response?.status() ?? 0,
      cacheControl: response?.headers()["cache-control"] ?? null,
      varyPresent: response?.headers().vary !== undefined,
      navigationRetries,
      consoleErrors: consoleErrors.length,
      pageErrors: pageErrors.length,
      axeVersion: axeAudit.version,
      axeRunProfile: axeAudit.runProfile,
      axeCompleted,
      axeViolations: axeAudit.violations.length,
      contractA11yCompleted,
      contractA11yViolations: contractA11yViolations.length,
      forbiddenStrings: cellFailures.filter((failure) => failure.startsWith("forbidden copy")).length,
      piiLeak: leakFindings.length > 0,
      artifacts,
      failures: cellFailures,
    };
    cells.push(cell);
    matrixFailures.push(...cellFailures.map((failure) => `${prefix}: ${failure}`));
    if (context) await context.close();
  }

  const fragment = `${JSON.stringify({ scenario: SCENARIO, viewport: width, cells }, null, 2)}\n`;
  atomicWrite(path.join(scenarioRoot, `${width}.fragment.json`), fragment);
  expect(matrixFailures, matrixFailures.join("\n")).toEqual([]);
});
