# WillowWealth Landing Page

## Overview

WillowWealth is a static marketing website for a private markets investment platform. The site serves as a landing page that showcases the company's products (managed portfolios, direct investments, and retirement accounts) and educates potential customers about private market investing opportunities.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Pure HTML/CSS/JavaScript**: The site uses vanilla technologies without any frontend framework
- **Static Site Design**: No build step required; files are served directly
- **Mobile-First Responsive Design**: CSS handles responsive layouts with flexbox and media queries
- **Animation Pattern**: Uses Intersection Observer API for scroll-triggered animations on cards

### Backend Architecture
- **Simple Node.js HTTP Server**: Minimal server (`server.js`) using native Node.js `http` and `fs` modules
- **Static File Serving**: Routes all requests to appropriate static files based on MIME types
- **Fallback Routing**: Returns `index.html` for any unmatched routes (SPA-style fallback)
- **Port Configuration**: Runs on port 5000, bound to 0.0.0.0 for external access

### Design System
- **Color Palette**: Defined via CSS custom properties (primary: #335859, accent: #002E30, background: #E6EDED)
- **Typography**: Uses Inter font from Google Fonts as primary typeface
- **Brand Assets**: SVG-based logo embedded inline for performance

## External Dependencies

### CDN Services
- **Google Fonts**: Inter font family loaded via fonts.googleapis.com

### No Database
- This is a static marketing site with no data persistence requirements

### No Authentication
- No user accounts or authentication system implemented

### No Third-Party APIs
- Currently no external API integrations

### Branding Assets
- JSON configuration files in `attached_assets/` contain brand specifications (colors, typography) for reference
- Markdown content files provide navigation structure and copy guidance