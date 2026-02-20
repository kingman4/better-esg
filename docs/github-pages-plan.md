# GitHub Pages Landing Page — Implementation Plan

## Goal

Create a single-page landing site at `kingman4.github.io/better-esg` (or custom domain) to explain the project and collect email signups from potential users. Target audience: regulatory affairs professionals and engineering teams at pharma/biotech companies.

## Email Signup: EmailJS

EmailJS sends email directly from the browser via JavaScript — no backend needed, works on static GitHub Pages.

**Free tier:** 200 emails/month, 2 email templates, 1 contact form.

### Setup Steps

1. Create account at emailjs.com
2. Connect your email service (Gmail, Outlook, etc.)
3. Create an email template with variables: `{{from_name}}`, `{{from_email}}`, `{{company}}`, `{{message}}`
4. Get three IDs: service ID, template ID, public key
5. Add the EmailJS SDK script + form handler to the landing page

### Form Fields

- **Email** (required) — the signup
- **Name** (optional) — personalization
- **Company** (optional) — helps you understand who's interested
- **Role** (optional, dropdown) — Regulatory Affairs / Engineering / Other
- **How did you find us?** (optional) — attribution

Keep it short. Every extra field reduces signups. Could start with just email + name.

### Code Pattern

```html
<script src="https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js"></script>
<script>
  emailjs.init("YOUR_PUBLIC_KEY");

  document.getElementById("signup-form").addEventListener("submit", function(e) {
    e.preventDefault();
    emailjs.sendForm("YOUR_SERVICE_ID", "YOUR_TEMPLATE_ID", this)
      .then(function() {
        // Show success message, hide form
      }, function(error) {
        // Show error message
      });
  });
</script>
```

### Spam Prevention

- EmailJS has built-in rate limiting
- Add a honeypot field (hidden input that bots fill, humans don't)
- Consider adding a simple question like "What does FDA stand for?" as a domain-specific captcha

## Page Structure

### Hero Section

Headline: "Open-Source FDA ESG NextGen Submissions"

Subheadline: "Submit regulatory documents to the FDA without expensive vendor software. One binary. No vendor lock-in. Free forever."

CTA button: "Get Early Access" → scrolls to signup form

### Problem / Solution (for decision-makers)

- Current FDA submission tools cost $50K–$200K+/year in licensing
- ESG NextGen is the FDA's modern API, replacing the legacy gateway
- Better ESG is a free, open-source alternative that handles the full workflow

### How It Works (for both audiences)

Visual 3-step flow:
1. Configure your FDA credentials
2. Upload your submission files
3. Track status through the web UI or CLI

Screenshot or GIF of the web UI showing the progress stepper.

### Technical Highlights (for engineers)

- Single Go binary — deploy anywhere, no runtime dependencies
- Handles files up to 1TB via streaming uploads
- Background polling for FDA status with acknowledgement storage
- REST API + Web UI + CLI — use whichever fits your workflow
- Multi-tenant with RBAC, MFA, audit logging
- Apache 2.0 licensed

### Signup Form

"Interested? Sign up for updates — we'll let you know when the hosted version is ready."

Form with EmailJS integration.

### Footer

Links: GitHub repo, Apache 2.0 license, contact email

## Technical Implementation

### File Structure

```
docs/
  index.html       — single-page landing site
  style.css        — styles (or inline in HTML)
  screenshot.png   — web UI screenshot for the page
```

### Hosting

GitHub Pages serves from the `docs/` folder on `main` (or `dev`). Enable in repo settings: Settings → Pages → Source → Deploy from branch → `main` (or `dev`) → `/docs` folder.

### Design

- Single HTML file, no build step, no framework
- Tailwind CSS via CDN for styling (consistent with the web UI)
- Mobile-responsive
- Dark/light color scheme that feels professional (pharma audience)
- Minimal JS — only EmailJS for the form

### Custom Domain (optional, later)

If you get a domain like `betteresg.com`:
1. Add CNAME file to `docs/` with the domain
2. Configure DNS A records to GitHub's IPs
3. Enable HTTPS in repo settings

## Rollout Plan

1. **Set up EmailJS** — create account, connect email, create template (~15 min)
2. **Build the landing page** — single `index.html` in `docs/` (~2-3 hours)
3. **Add a screenshot** — take a screenshot of the web UI submission detail page
4. **Enable GitHub Pages** — repo settings, pick branch + `/docs` folder (~2 min)
5. **Test the form** — submit a test signup, verify email arrives
6. **Promote** — Show HN post, LinkedIn, Reddit (see promotion plan)

## Success Metrics

- **Week 1:** Page is live, form works, first promotion post is up
- **Month 1:** 20+ email signups = strong signal, worth investing more
- **Month 1:** <5 signups = rethink messaging or audience targeting

## Cost

$0. GitHub Pages is free. EmailJS free tier covers 200 emails/month. No infrastructure to maintain.
