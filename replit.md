# WillowWealth Landing Page

## Overview

WillowWealth is a marketing website for a private markets investment platform. The site serves as a landing page and includes authentication (Google OAuth, Apple Sign-In placeholder, email/password), a mandatory onboarding flow (legal name confirmation), and a user dashboard.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Pure HTML/CSS/JavaScript**: The site uses vanilla technologies without any frontend framework
- **Static Site Design**: No build step required; files are served directly
- **Mobile-First Responsive Design**: CSS handles responsive layouts with flexbox and media queries
- **Animation Pattern**: Uses Intersection Observer API for scroll-triggered animations on cards
- **Auth Pages**: Login, signup, forgot-password pages with consistent styling (accent: #013536, buttons: #a2f2b7)
- **Signup Flow**: Two-screen design - main screen (social auth + email button) and email signup screen (form with legal consent)
- **Onboarding Flow**: Mandatory legal name confirmation page after signup/login, server-enforced
- **Intercom Chat**: Widget integrated on all pages (app_id: ub97p16r) with floating chat prompt on landing page

### Backend Architecture
- **Simple Node.js HTTP Server**: Minimal server (`server.js`) using native Node.js `http`, `fs`, `crypto`, `pg`, and `bcryptjs` modules
- **PostgreSQL Database**: Stores users, onboarding status, hashed passwords via `pg` pool
- **Static File Serving**: Routes all requests to appropriate static files based on MIME types
- **Fallback Routing**: Returns `index.html` for any unmatched routes (SPA-style fallback)
- **Port Configuration**: Runs on port 5000, bound to 0.0.0.0 for external access
- **OAuth Authentication**: Google OAuth 2.0 implemented with CSRF-protected state parameter (cookie-bound), token exchange, and session management
- **Apple Sign-In**: Placeholder ready with same interface pattern; needs APPLE_CLIENT_ID credentials to activate
- **Email Auth**: Signup with bcrypt-hashed passwords, login with credential validation
- **Email Verification**: Uses nodemailer with Gmail transporter (EMAIL_USER, EMAIL_PASS env vars)
- **Session Management**: In-memory session store with HttpOnly cookies, 24-hour expiry
- **Onboarding Enforcement**: Server-side middleware checks onboarding status on protected pages; redirects to correct step

### Onboarding System
- **Sequential Steps**: Defined as ordered array `ONBOARDING_STEPS` in server.js
- **Current Steps**: `legal_name_completed` → `/legal-name.html`
- **Server Enforcement**: Protected pages (`/dashboard.html`, `/legal-name.html`) check auth + onboarding status
- **Database Fields**: `legal_name_completed`, `onboarding_completed` booleans on users table
- **Resume Logic**: On login, user is redirected to their next incomplete onboarding step
- **Extensible**: Add new steps to `ONBOARDING_STEPS` array with a `key` and `page` property

### Auth Routes
- `GET /auth/google?mode=login|signup` - Initiates Google OAuth flow
- `GET /auth/google/callback` - Google OAuth callback handler
- `GET /auth/apple?mode=login|signup` - Initiates Apple Sign-In flow
- `POST /auth/apple/callback` - Apple Sign-In callback handler
- `GET /auth/status` - Returns auth status + onboarding status (JSON)
- `GET /auth/logout` - Clears session and redirects to homepage
- `GET /auth/error` - Displays Google OAuth configuration troubleshooting page

### API Routes
- `POST /api/signup` - Email signup (creates user, session, sends verification email)
- `POST /api/login` - Email login (validates credentials, creates session, returns onboarding redirect)
- `POST /api/onboarding/legal-name` - Saves legal name, marks step complete
- `GET /api/onboarding/status` - Returns current onboarding progress
- `POST /send-verification` - Sends email verification

### Database Schema (PostgreSQL)
- **users** table:
  - `id` SERIAL PRIMARY KEY
  - `email` VARCHAR(255) UNIQUE NOT NULL
  - `name` VARCHAR(255)
  - `picture` TEXT
  - `provider` VARCHAR(50) NOT NULL (google, apple, email)
  - `provider_id` VARCHAR(255)
  - `password_hash` VARCHAR(255)
  - `legal_first_name` VARCHAR(255)
  - `legal_last_name` VARCHAR(255)
  - `legal_name_completed` BOOLEAN DEFAULT FALSE
  - `onboarding_completed` BOOLEAN DEFAULT FALSE
  - `created_at` TIMESTAMP
  - `updated_at` TIMESTAMP

### Design System
- **Color Palette**: Defined via CSS custom properties (primary: #335859, accent: #002E30, background: #E6EDED)
- **Auth Colors**: Buttons #a2f2b7, checkboxes/text #013536, email signup button #013536
- **Typography**: Uses Inter font from Google Fonts as primary typeface
- **Brand Assets**: SVG-based logo in images/auth/logo.svg

## External Dependencies

### CDN Services
- **Google Fonts**: Inter font family loaded via fonts.googleapis.com
- **Font Awesome**: Icon library for UI elements (eye toggle, etc.)

### NPM Packages
- `pg` - PostgreSQL client for Node.js
- `bcryptjs` - Password hashing
- `nodemailer` - Email sending

### Environment Variables (Secrets)
- `DATABASE_URL` - PostgreSQL connection string (auto-configured)
- `EMAIL_USER` - Gmail address for sending verification emails
- `EMAIL_PASS` - Gmail app password for email sending
- `GOOGLE_CLIENT_ID` - Google OAuth Client ID (required for Google Sign-In)
- `GOOGLE_CLIENT_SECRET` - Google OAuth Client Secret (required for Google Sign-In)
- `APPLE_CLIENT_ID` - Apple Service ID (future, for Apple Sign-In)

### Branding Assets
- JSON configuration files in `attached_assets/` contain brand specifications (colors, typography) for reference
- Auth images in `images/auth/` (logo, welcome card, secure badge)
