# ProofMint Design Guidelines - MultiversX Style

## Design Approach

**Selected Approach:** MultiversX Explorer Inspired Design System

**Justification:** ProofMint is a blockchain certification platform built on MultiversX. The interface should reflect the MultiversX ecosystem's visual identity - modern, tech-forward, and trustworthy. Drawing from MultiversX Explorer and xPortal's design language while maintaining accessibility for non-technical users.

**Core Principle:** "Web3 innovation meets professional certification" - The interface should feel cutting-edge yet credible, like exploring the blockchain itself.

## Color Palette

### Dark Mode (Primary)
- **Background Base:** 222 13% 5% (deep charcoal #0B0C10 - MultiversX signature)
- **Surface:** 220 13% 9% (elevated cards)
- **Primary Brand:** 194 100% 50% (cyan blue #00C2FF - MultiversX primary)
- **Secondary Brand:** 255 67% 69% (purple #7B61FF - MultiversX accent)
- **Success/Verified:** 156 100% 50% (neon green #00FFA3)
- **Text Primary:** 0 0% 100%
- **Text Secondary:** 0 0% 63% (#A1A1AA)
- **Border Subtle:** 220 10% 15%

### Light Mode
- **Background Base:** 0 0% 98%
- **Surface:** 0 0% 100%
- **Primary Brand:** 194 100% 50% (consistent cyan)
- **Secondary Brand:** 255 67% 69% (consistent purple)
- **Text Primary:** 0 0% 10%
- **Text Secondary:** 0 0% 40%

**Accent Usage:** Cyan blue (#00C2FF) for primary CTAs and active states. Purple (#7B61FF) for secondary highlights. Neon green (#00FFA3) for verification and success states.

## Typography

**Font Stack:**
- **Display/Headings:** Orbitron (MultiversX signature font) - futuristic, tech-forward
- **Primary:** Space Grotesk (navigation, labels) - modern, Web3-aligned
- **Body:** Inter (body text, forms, data) - clean, highly legible

**Scale:**
- **Hero Heading:** text-6xl font-bold (60px) - landing page impact
- **Section Headings:** text-3xl font-semibold (30px)
- **Card Titles:** text-xl font-medium (20px)
- **Body Text:** text-base (16px) - optimal readability
- **Metadata/Labels:** text-sm text-secondary (14px)
- **Micro Copy:** text-xs (12px) - timestamps, hash displays

## Layout System

**Spacing Primitives:** Use Tailwind units of 4, 6, 8, 12, 16, 24 (p-4, gap-6, my-8, py-12, etc.)

**Container Strategy:**
- **Full-width sections:** w-full with inner max-w-7xl mx-auto px-6
- **Content areas:** max-w-6xl mx-auto
- **Dashboard content:** max-w-5xl
- **Forms:** max-w-2xl

**Grid Patterns:**
- **Features:** grid-cols-1 md:grid-cols-3 gap-8
- **Dashboard cards:** grid-cols-1 lg:grid-cols-2 gap-6
- **Certification history:** Single column with horizontal card layout

## Component Library

### Navigation
- **Top Bar:** Sticky header with logo left, nav center, CTA/user menu right
- **Logo:** "ProofMint" wordmark with seal icon, cyan glow on hover
- **Nav Links:** Clean text links with cyan underline on hover
- **CTA Button:** Primary cyan button with glow effect

### Core UI Elements

**Upload Zone:**
- Large dashed border box with cyan accent on drag-over
- Center-aligned icon (document with shield/checkmark)
- "Drop your file here or click to browse" text
- Supported formats displayed below
- Progress bar with cyan fill and glow during upload

**Certification Cards (Dashboard):**
- Dark surface with subtle border and cyan glow on hover
- Left: File type icon with cyan background
- Center: Filename, date, hash preview (truncated with tooltip)
- Right: Status badge + action menu (download certificate, view proof)
- Transaction link with external icon and purple accent

**Proof Verification Display:**
- Hero section with large verification seal icon
- Filename display (non-downloadable)
- Hash shown in monospace font with copy button
- Timestamp with calendar icon
- Prominent "View on MultiversX Explorer" button (cyan)
- Certificate download CTA (purple)

**Pricing Cards:**
- Three-column layout (Free, Pro, Business)
- Cyan highlight on recommended plan with glow
- Clear feature list with checkmarks
- Pricing displayed prominently
- "Start Plan" CTA button with hover glow

### Glass Morphism Effects
- **Cards:** backdrop-filter blur(12px) with rgba(255, 255, 255, 0.04) overlay
- **Borders:** 1px solid rgba(255, 255, 255, 0.08)
- **Hover:** Cyan border glow: 0 0 12px rgba(0, 194, 255, 0.4)

### Forms
- Clean input fields with cyan focus rings and glow
- Labels above inputs, help text below
- File upload with drag-drop zone and cyan accent
- Submit buttons in cyan with glow effect and loading states

### Data Display
- **Transaction Hashes:** Monospace font, truncated with expand/copy
- **Timestamps:** Relative time with absolute tooltip
- **Status Badges:** Pill-shaped with icon (Verified, Pending, Failed)
- **QR Codes:** Generated dynamically, placed on certificates and public proof pages

### Overlays
- **Modals:** Centered with backdrop blur, max-w-lg, dark glass effect
- **Toast Notifications:** Top-right, cyan for success, red for errors
- **Certificate Preview:** Modal with PDF viewer before download

## Landing Page Strategy

**Hero Section (80vh):**
- Split layout: Left side with heading, tagline, CTA; Right side with animated certification flow visualization
- Heading: "Certify what you create. In one click." (Orbitron font)
- Subheading: "Blockchain-secured proof of ownership. No coding required."
- Primary CTA: "Certify Your First File Free" (cyan with glow)
- Trust indicator: "Powered by MultiversX Truth Machine" with logo

**How It Works (3 Steps):**
- Horizontal timeline with numbered circles (cyan)
- Upload → Hash → Certify workflow
- Visual icons for each step with cyan/purple accents
- Brief explanatory text

**Benefits Grid:**
- Three columns: 🔒 Immutable Proof | ⚡ Instant Certification | 🧾 Public Verification
- Each with icon, heading, description
- Cyan/purple gradient accents

**Use Cases:**
- Target audience showcase: Designers, Lawyers, Musicians, Agencies
- Card layout with profession icon and specific use case
- Glass morphism cards with cyan borders

**Pricing Preview:**
- Simplified tier comparison
- "View All Plans" link to dedicated pricing page

**Trust Section:**
- "Built on MultiversX" branding
- Blockchain verification explanation with cyan highlights
- Security reassurance with lock icons

**Footer:**
- Dark background (#0B0C10) with cyan accents
- Quick links, API documentation, social media
- Newsletter signup: "Get updates on blockchain certification"

## Images

**Hero Image:** Abstract visualization of blockchain verification - geometric patterns forming a certification seal, cyan and purple gradients on dark background.

**How It Works Illustrations:** Three sequential isometric illustrations showing file upload, hash computation, and blockchain certification process with cyan/purple accents.

**Use Case Images:** Professional stock photos of target users (designer at desk, lawyer reviewing documents, musician with headphones) - authentic, diverse, modern workplace settings.

## Animations

**Minimal and Purposeful:**
- Upload zone: Subtle bounce on drag-over with cyan glow
- Certification complete: Checkmark animation (1 second) with green glow
- Transaction confirmation: Pulse effect on verification badge with cyan glow
- Page transitions: Smooth fade (300ms)
- Button hover: Subtle glow effect on cyan/purple buttons

**Glow Effects:**
- Primary buttons: box-shadow: 0 0 16px rgba(0, 194, 255, 0.3) on hover
- Cards: box-shadow: 0 0 12px rgba(0, 194, 255, 0.4) on hover
- Success states: box-shadow: 0 0 12px rgba(0, 255, 163, 0.4)

**No Distracting Effects:** No parallax scrolling, no floating elements, no constant motion.
