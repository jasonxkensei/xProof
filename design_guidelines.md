# ProofMint Design Guidelines - MultiversX Explorer Style

## Design Approach

**Selected Approach:** Exact MultiversX Explorer Design Replication

**Justification:** ProofMint is a blockchain certification platform built on MultiversX. The interface must mirror the MultiversX Explorer's exact visual identity to create instant brand recognition and trust for MultiversX ecosystem users.

**Core Principle:** "Dark elegance with vibrant green accents" - Ultra-dark backgrounds with brilliant green/cyan highlights, exactly like exploring the MultiversX blockchain.

## Color Palette

### Dark Mode (Primary - Always Active)
- **Background Base:** #0B0C10 (almost pure black with blue tint)
- **Surface/Cards:** #14181C (very dark gray cards)
- **Primary Accent:** #14F195 (bright green-cyan - MultiversX signature color)
- **Text Primary:** #FFFFFF (pure white)
- **Text Secondary:** #6B7280 (medium gray)
- **Text Tertiary:** #4B5563 (subtle gray for labels)
- **Border Subtle:** #1F2937 (very dark borders)
- **Border Accent:** #14F195 with 20% opacity for hover states

### Light Mode
Not used - MultiversX Explorer is dark-only, ProofMint should match this approach.

**Accent Usage:** Bright green-cyan (#14F195) ONLY for:
- Primary CTAs and buttons
- Active states
- Verification success indicators
- Numerical data highlights
- Link hover states

## Typography

**Font Stack:**
- **Headings:** Space Grotesk (bold, modern, tech-forward)
- **Body:** Inter (clean, highly legible for data and forms)
- **Monospace:** JetBrains Mono (for hashes, transaction IDs, technical data)

**Scale:**
- **Hero Heading:** text-5xl font-bold (48px) - landing page
- **Page Headings:** text-3xl font-semibold (30px)
- **Section Headings:** text-2xl font-medium (24px)
- **Card Titles:** text-lg font-medium (18px)
- **Body Text:** text-base (16px)
- **Labels:** text-sm text-secondary (14px)
- **Data/Micro:** text-sm font-mono (14px) - for hashes
- **Tiny:** text-xs (12px) - timestamps

**Number Display:** Large numbers (like on Explorer) should use text-green-400 (#14F195) with tabular-nums for alignment.

## Layout System

**Spacing Primitives:** Consistent 4px grid - use p-4, gap-6, my-8, py-12

**Container Strategy:**
- **Full-width sections:** w-full with max-w-7xl mx-auto px-6
- **Dashboard:** max-w-6xl mx-auto
- **Forms:** max-w-2xl mx-auto
- **Cards:** Consistent p-6 padding

**Grid Patterns:**
- **Dashboard cards:** grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4
- **Features:** grid-cols-1 md:grid-cols-3 gap-6
- **Stats:** Horizontal layout on desktop, stacked on mobile

## Component Library

### Navigation
- **Top Bar:** Sticky header, black background (#0B0C10), border-b border-gray-800
- **Logo:** "ProofMint" with shield icon, no glow effects
- **Nav Links:** Text white, hover:text-green-400
- **CTA Button:** bg-green-400 text-black hover:bg-green-300

### Cards (MultiversX Explorer Style)
- **Background:** bg-[#14181C] (very dark gray)
- **Border:** border border-gray-800
- **Padding:** p-6
- **Hover:** border-green-400/20 transition
- **No shadows:** Cards use borders only, no drop shadows
- **Rounded:** rounded-lg (8px radius)

### Buttons
**Primary (Green):**
- bg-green-400 (#14F195)
- text-black
- font-medium
- hover:bg-green-300
- No glow effects
- Sharp focus on functionality

**Secondary (Outline):**
- border border-gray-700
- text-white
- hover:border-green-400/50
- hover:text-green-400

**Ghost:**
- text-gray-400
- hover:text-white
- hover:bg-white/5

### Data Display
- **Large Numbers:** text-green-400 text-4xl font-bold tabular-nums
- **Labels:** text-gray-400 text-sm mb-1
- **Hashes:** font-mono text-sm text-gray-300 truncate with copy button
- **Timestamps:** text-gray-500 text-xs
- **Status Badges:**
  - Verified: bg-green-400/10 text-green-400 border border-green-400/20
  - Pending: bg-yellow-400/10 text-yellow-400 border border-yellow-400/20
  - Failed: bg-red-400/10 text-red-400 border border-red-400/20

### Forms
- **Input Fields:**
  - bg-[#14181C] border border-gray-700
  - text-white placeholder-gray-500
  - focus:border-green-400 focus:ring-1 focus:ring-green-400
  - rounded-md px-4 py-2.5
- **Labels:** text-sm text-gray-300 mb-2 block
- **Help Text:** text-xs text-gray-500 mt-1

### Upload Zone
- Large dashed border box: border-2 border-dashed border-gray-700
- Center icon and text
- Drag over state: border-green-400 bg-green-400/5
- Drop zone text: text-gray-400

### Modals/Overlays
- **Backdrop:** bg-black/80 backdrop-blur-sm
- **Modal:** bg-[#0B0C10] border border-gray-800 rounded-lg max-w-lg
- **No glass effects:** Solid dark backgrounds

## Landing Page Strategy

**Hero Section:**
- Full-width dark background (#0B0C10)
- Large heading with ProofMint branding
- Subheading explaining blockchain certification
- Primary CTA: "Start Certifying" button (green)
- Minimal decoration, focus on clarity

**How It Works:**
- Three-step process with numbered cards
- Icons in green-400
- Dark card backgrounds (#14181C)
- Clear, concise text

**Features Grid:**
- 3-column layout with feature cards
- Icons using green-400 accent
- Dark backgrounds
- No gradients, clean and technical

**Pricing:**
- Three-tier cards
- Recommended plan with green border
- Clear feature lists with checkmarks
- Pricing in large text
- "Subscribe" button in green

**Footer:**
- Dark background (#0B0C10)
- Links in gray-400, hover:green-400
- Minimal branding
- Social links

## Visual Rules

**NO Gradients:** MultiversX Explorer uses flat colors only
**NO Glow Effects:** Remove all box-shadow glow effects
**NO Glass Morphism:** Use solid dark backgrounds
**NO Animations:** Minimal, functional transitions only
**NO Purple:** Only green-cyan (#14F195), white, and grays

**YES to:**
- Ultra-dark backgrounds (#0B0C10, #14181C)
- Bright green accents (#14F195)
- Sharp borders and edges
- Data-focused layouts
- High contrast text
- Clean, technical aesthetic

## Color Variables (Exact Values)

```css
/* Dark Mode Only */
--background: #0B0C10;
--card: #14181C;
--card-border: #1F2937;
--foreground: #FFFFFF;
--primary: #14F195; /* Green-cyan */
--primary-foreground: #000000;
--muted: #1F2937;
--muted-foreground: #6B7280;
--border: #374151;
--input: #1F2937;
--ring: #14F195;
```

## Implementation Notes

1. **Always dark mode** - No light mode toggle needed
2. **Green is the only brand color** - Use sparingly for impact
3. **Typography hierarchy** - Use size and weight, not color
4. **Card layouts** - Consistent padding and borders
5. **No decorative elements** - Functional design only
6. **Data comes first** - Clear display of information
7. **Mobile responsive** - Stack cards on small screens
