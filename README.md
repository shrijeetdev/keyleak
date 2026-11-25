# KeyLeak

**Client-side JavaScript secret scanner and Shadow DOM bookmarklet to find exposed API keys, tokens, and credentials in frontend web bundles before attackers do.**

![License: MIT](https://img.shields.io/badge/License-MIT-3FB950?style=flat-square)
![Built with JavaScript](https://img.shields.io/badge/JavaScript-Vanilla_ES6-15E0ED?style=flat-square)
[![Live Demo](https://img.shields.io/badge/Live_Demo-GitHub_Pages-3FB950?style=flat-square)](https://shrijeetdev.github.io/keyleak/)
![Privacy: No Uploads](https://img.shields.io/badge/Privacy-No_Uploads_%7C_100%25_Local-0D1117?style=flat-square)

**[▶ Open the live tool](https://shrijeetdev.github.io/keyleak/)**

---

## Why KeyLeak Exists

Fast-shipped web applications and AI-generated frontends frequently bundle private backend secrets directly into public JavaScript chunks. Build tools such as Vite, Next.js, and Webpack automatically inline environment variables prefixed with `VITE_` or `NEXT_PUBLIC_` into compiled assets served to every visitor.

A single leaked credential in a production bundle carries immediate financial and security consequences:

- **Stripe Secret Keys (`sk_live_`)**: Attackers can issue unauthorized refunds, read customer records, or alter payout configurations.
- **Supabase `service_role` JWTs**: Unlike the public `anon` key, the `service_role` token completely bypasses Row-Level Security (RLS) policies, granting full read/write administrative access to every table in your database.
- **OpenAI & Anthropic API Keys**: Automated bots continuously scrape newly deployed JavaScript bundles to drain API billing quotas within minutes.

KeyLeak gives developers and site owners an instant, zero-upload way to audit build outputs and live pages before shipping.

---

## Features

- **Local Paste & Drag-and-Drop Scanner**: Paste raw JavaScript, HTML, `.env` files, or minified bundle text, or drop multiple `.js`, `.mjs`, `.cjs`, `.map`, `.html`, `.env`, `.json`, and `.ts` files read locally via the browser `FileReader` API.
- **Self-Contained Live Site Bookmarklet**: Dynamically generated at runtime from the exact same detector engine—with zero external script dependencies. When triggered on your own website, it collects inline `<script>` blocks and fetches same-origin script URLs (`credentials: "same-origin"`), then renders an isolated audit overlay inside a **Shadow DOM** host so site CSS cannot break the report.
- **24 Secret Detectors with Entropy & Payload Validation**: Combines vendor prefix/length rules with Shannon entropy scoring, placeholder filtering, and Base64 JWT payload decoding to separate real credentials from random webpack chunk hashes.
- **Context-Aware Severity Classification**: Distinguishes `CRITICAL` and `HIGH` backend secrets from `INFO` publishable client identifiers (such as Stripe `pk_live_`, Razorpay `rzp_live_`, Google Maps/Firebase browser keys, and Supabase `anon` tokens).
- **Safe Secret Masking & Filtered Exports**: Displays only the first 6 and last 4 characters of any detected secret (`prefix...last`), calculates line numbers, provides concrete remediation steps, supports severity filtering (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `INFO`), and exports masked reports as **JSON** or **Markdown**.
- **Runtime Synthetic Sample Generator**: Includes a **Try a sample** button that constructs synthetic keys dynamically via string concatenation at runtime so the repository never triggers secret-scanning false alarms.

---

## Detected Key Types

| Detector | Severity | Public by Design? | Validation & Context |
| :--- | :--- | :--- | :--- |
| **AWS Access Key ID** | `HIGH` | No | 20-char `AKIA` / `ASIA` / `AROA` / `AIDA` prefix check |
| **AWS Secret Access Key** | `CRITICAL` | No | Assignment context + 40-char Base64 + Shannon entropy `>= 4.2` |
| **GitHub PAT / OAuth Token** | `CRITICAL` | No | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` + entropy `>= 3.8` |
| **GitLab Personal Access Token** | `CRITICAL` | No | `glpat-` prefix + length `>= 26` + entropy `>= 3.5` |
| **Slack Bot / User / App Token** | `CRITICAL` | No | `xox[baprs]-` structure + entropy `>= 3.6` |
| **Slack Incoming Webhook URL** | `HIGH` | No | `hooks.slack.com/services/T.../B.../...` structure |
| **Stripe Secret / Restricted Live Key** | `CRITICAL` | No | `sk_live_` / `rk_live_` prefix + entropy `>= 3.7` |
| **Stripe Live Publishable Key** | `INFO` | **Yes** | `pk_live_` prefix; flagged as informational for domain check |
| **OpenAI API Key** | `CRITICAL` | No | `sk-` / `sk-proj-` / `sk-svcacct-` prefix + length `>= 40` + entropy `>= 3.8` |
| **Anthropic Claude API Key** | `CRITICAL` | No | `sk-ant-api03-` / `sk-ant-admin01-` prefix + entropy `>= 4.0` |
| **Google Cloud / Maps / Firebase API Key** | `INFO` | **Yes** | 39-char `AIza` prefix; advises HTTP referrer & API restrictions |
| **Firebase Web SDK Config Object** | `INFO` | **Yes** | `apiKey` + `projectId` block; reminds to audit Firestore/RTDB rules |
| **Supabase `service_role` Key** | `CRITICAL` | No | Decodes JWT payload; flags `iss: supabase` + `role: service_role` |
| **Supabase `anon` Key** | `INFO` | **Yes** | Decodes JWT payload; flags `iss: supabase` + `role: anon` |
| **Generic Hardcoded JWT** | `MEDIUM` | No | Valid 3-segment Base64Url JSON Web Token decoding |
| **Twilio Account / API Key SID** | `HIGH` | No | 34-char `AC` / `SK` hex identifier + entropy `>= 3.2` |
| **SendGrid API Key** | `CRITICAL` | No | 69-char `SG.<22>.<43>` structure + entropy `>= 4.0` |
| **Mailgun Private API Key** | `CRITICAL` | No | 36-char `key-` hex key + entropy `>= 3.3` |
| **Razorpay Live Key Secret** | `CRITICAL` | No | Secret assignment context + 24-char token + entropy `>= 3.6` |
| **Razorpay Live Key ID** | `INFO` | **Yes** | 23-char `rzp_live_` identifier for Checkout.js |
| **Discord Bot Token** | `CRITICAL` | No | 3-part `[MN]...` token structure + entropy `>= 4.0` |
| **Discord Webhook URL** | `HIGH` | No | `discord.com/api/webhooks/...` endpoint URL |
| **Telegram Bot API Token** | `CRITICAL` | No | Numeric bot ID + `:AA` 35-char token + entropy `>= 3.6` |
| **Private Cryptographic Key (PEM / OpenSSH)** | `CRITICAL` | No | `-----BEGIN ... PRIVATE KEY-----` block detection |
| **Database Connection URI with Password** | `CRITICAL` | No | `postgres://`, `postgresql://`, `mysql://`, `mongodb+srv://`, `redis://` |
| **High-Entropy Secret / Password Assignment** | `MEDIUM` | No | Sensitive variable names (`api_secret`, `db_password`, etc.) + entropy `>= 3.6` |

---

## How to Use

### 1. Paste or Drop Code Scanner

1. Open https://shrijeetdev.github.io/keyleak/ in any modern desktop or mobile browser.
2. Paste compiled JavaScript, HTML source, or `.env` contents into the **Scan code** editor—or click **Upload files** / drag and drop local `.js`, `.map`, `.html`, `.env`, or `.json` files directly onto the dropzone.
3. Click **Scan now** (file uploads scan automatically).
4. Filter results by severity (`All`, `Critical`, `High`, `Medium`, `Info`) and export masked audit reports via **Export JSON** or **Export Markdown**.

### 2. Install & Run the Live Site Bookmarklet

1. Ensure your browser's bookmarks bar is visible (`Ctrl+Shift+B` on Windows/Linux, `Cmd+Shift+B` on macOS).
2. Drag the **KeyLeak Live Scan** button from the KeyLeak page directly onto your bookmarks bar (or click **Copy code** and save it as the URL of a new bookmark).
3. Navigate to **your own deployed website** (e.g., staging or production).
4. Click **KeyLeak Live Scan** in your bookmarks bar. KeyLeak will inspect the rendered HTML, inline `<script>` tags, and same-origin `.js` bundles, displaying an isolated Shadow DOM modal with any masked findings. Click **Close** to remove the overlay cleanly.

---

## What to Do If You Find a Leak

Treat any secret that has ever been committed to a repository or served in a public bundle as compromised:

1. **Rotate immediately**: Revoke and regenerate the exposed key or database password in the provider's dashboard before doing anything else.
2. **Move to server-side environment variables**: Remove `NEXT_PUBLIC_`, `VITE_`, or `REACT_APP_` prefixes from private secrets. Store the rotated key in a server-only environment variable and proxy third-party API requests through a backend route or serverless function.
3. **Restrict public-by-design keys**: For client keys (`AIza...`, `pk_live_`, Supabase `anon`), enforce strict HTTP referrer allowlists, API scope restrictions, and database Row-Level Security (RLS) policies.
4. **Audit access logs**: Review provider billing dashboards, CloudTrail, or database audit logs for unauthorized activity during the exposure window.

---

## How It Works & Limitations

- **Detection Pipeline**: KeyLeak runs a multi-stage static analysis pass over input strings: regular expression matching for known key formats, length and character-set assertions, Shannon entropy calculation (`H = -Σ p(x) log2 p(x)`) to filter out low-entropy placeholders, and Base64Url JSON decoding for JWTs to inspect `iss` and `role` claims.
- **False Positives**: Minified bundles occasionally contain high-entropy random identifiers, hashes, or test fixtures that resemble generic secret assignments. Always verify findings against your actual configuration.
- **Scope Limits**: KeyLeak only inspects client-accessible text, uploaded files, and same-origin browser scripts. It cannot inspect server-side source code, cross-origin scripts blocked by CORS, or encrypted runtime secrets.

---

## Privacy

**Nothing leaves your browser.** KeyLeak is a single static HTML file with zero backend infrastructure, zero analytics, zero CDNs, and zero external network requests. Files dropped into the scanner are read strictly in memory using the browser's `FileReader` API, and the bookmarklet only fetches scripts from the same origin you are actively viewing.

---

## Ethical Use

KeyLeak is designed as a defensive self-audit and pre-deployment verification tool for developers and security teams. **Only scan websites, repositories, and build artifacts that you own or have explicit written authorization to test.**

---

## Run Locally & Deploy on GitHub Pages

Because KeyLeak has zero build steps or dependencies, you can run it locally or host your own copy in seconds:

~~~bash
git clone https://github.com/shrijeetdev/keyleak.git
cd keyleak
# Open index.html directly in your browser, or serve locally:
python3 -m http.server 8080
~~~

To deploy your own instance on **GitHub Pages**:

1. Fork https://github.com/shrijeetdev/keyleak on GitHub.
2. Go to **Settings > Pages** in your forked repository.
3. Under **Build and deployment**, select **Deploy from a branch**, choose `main` and `/ (root)`, and click **Save**.

---

## Contributing

Contributions and new secret detectors are welcome. To add a new detector rule:

1. Open `index.html` and locate the `RULES` array inside `createScannerEngine()`.
2. Add an entry with a unique `id`, descriptive `name`, accurate default `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, or `INFO`), tight `regex`, a `validate` function (checking length, Shannon entropy, or payload structure to minimize false positives), and actionable `fix` guidance.
3. If adding a synthetic test case to `generateSampleCode()`, construct the fake credential via runtime string concatenation so automated repository secret scanners never flag the source file.
4. Submit a pull request to https://github.com/shrijeetdev/keyleak.

---

## License

Released under the **MIT License**. See `LICENSE` in https://github.com/shrijeetdev/keyleak for full terms.

---

Made by [Shrijeet Singh](https://github.com/shrijeetdev) · https://shrijeetsingh.com. If this saved you time, a ⭐ helps others find it.
