# Backend README - ITC ISMS Platform API

## Stack

- Node.js (ESM)
- Express
- Supabase JS (service role)
- OpenAI SDK
- Multer (file uploads)
- Security middleware: Helmet, HPP, Rate Limiting
- UA parser: `ua-parser-js` (security logging)

## Scripts

```bash
npm start   # run server
npm run dev # run with watch mode
```

Default port: `3001`

## Environment Variables

Use `backend/.env.example` as source of truth.

Required:

```env
SUPABASE_URL=...
SUPABASE_SERVICE_ROLE_KEY=...
PORT=3001
```

Recommended:

```env
NODE_ENV=development
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
REQUIRE_AUTH=true
OPENAI_API_KEY=...
SECURITY_LOG_HASH_IP=true
SECURITY_LOG_HASH_SALT=<strong-random-secret>
```

## Major Functional Areas

- Assessment lifecycle and step dependency orchestration
- ISMS smart questions/answers and preview/final generation
- GAP controls/reporting pipeline
- Risk profile/asset ingestion and risk generation
- SOA auto-generation and save
- Organization, policy, risk, task, evidence CRUD APIs
- Document section generation/assembly/export
- Security logging + admin log retrieval

## Core API Groups (high-level)

- Assessment and questions:
  - `/api/start`
  - `/api/assessment/*`
  - `/api/questions/:docType`
  - `/api/check/:docType`
- ISMS/GAP/Risk/SOA engines:
  - `/api/isms/*`
  - `/api/gap/*`
  - `/api/risk/*`
  - `/api/soa/*`
- Document workflows:
  - `/api/upload/:docType`
  - `/api/documents/preview/:docType`
  - `/api/documents/generate-section`
  - `/api/documents/assemble/:docType`
  - `/api/documents/export/:docType`
- Operational CRUD:
  - `/api/organizations`
  - `/api/policies*`
  - `/api/risks*`
  - `/api/tasks*`
  - `/api/evidence*`
- Security:
  - `GET /api/security/logs` (admin/security roles only)
  - `GET /health/security-logs` (admin/security roles only)
  - `GET /api/health`

## Security Controls Implemented

- `helmet` for baseline HTTP header hardening
- `hpp` against HTTP parameter pollution
- request rate limiting (`writeLimiter`, `authLimiter`)
- explicit CORS origin allowlist
- auth middleware using Supabase bearer-token validation
- upload controls:
  - file type allowlist
  - max file size limits
  - sanitized filenames

## Security Logging System

Implemented in `services/securityLogService.js`.

Captured fields (security-only scope):

- org_id, user_id
- ip_address (hashed by default)
- browser, os, device_type
- raw user-agent
- action, endpoint, method, status_code, created_at

Behavior:

- non-blocking queue-based inserts
- event-based logging for important actions
- anomaly events:
  - `anomaly_multi_ip_auth_failures`
  - `anomaly_new_device`

Admin retrieval:

- `GET /api/security/logs?user_id=&action=&from=&to=&limit=`

Health check:

- `GET /health/security-logs`

Retention:

- SQL helper: `public.purge_security_logs(retention_days integer default 90)`

## Database Schema

Primary schema file:

- `backend/schema.sql`

Includes:

- application tables (organizations, policies, risks, tasks, evidence, etc.)
- normalized assessment tables
- generated document/log tables
- security logs table and policies
- RLS enablement and baseline policies

## Operational Notes

- `requireAuth` can be relaxed in non-production with `REQUIRE_AUTH=false` (not recommended for shared/staging).
- Some endpoints still support backward-compatible behavior for earlier workflow variants.
- Keep service-role key server-side only.

## Troubleshooting

- **401 Missing Bearer token:** frontend request missing auth header or expired token.
- **403 Admin role required:** user role not in allowed admin/security set.
- **Upload errors:** check file type/size and upload path permissions.
- **Supabase errors:** validate URL/key, table existence, and RLS/policies.
- **No security log writes:** check `security_logs` schema/FKs and backend runtime logs.
# ITC ISMS Backend

Node.js/Express backend API for ISO 27001 Compliance Platform.

## Prerequisites

- Node.js 18+
- npm or yarn

## Setup

```bash
# Install dependencies
npm install

# Set environment variables
cp .env.example .env
# Edit .env with your Supabase credentials

# Start the server
npm start
```

The server will run on `http://localhost:3001`.

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SUPABASE_URL` | Your Supabase project URL | Yes |
| `SUPABASE_SERVICE_KEY` | Service role key for admin access | Yes |
| `PORT` | Server port (default: 3001) | No |

## API Endpoints

### Health Check
```
GET /api/health
```

### Organization
```
GET    /api/organization
POST   /api/organization
```

### Assessment
```
POST   /api/assessment/init
POST   /api/assessment/answer
GET    /api/assessment/summary/:id
GET    /api/assessment/resume/:id
POST   /api/assessment/complete/:id
GET    /api/assessment/report/:id
```

### Policies
```
GET    /api/policies
POST   /api/policies
PUT    /api/policies/:id
DELETE /api/policies/:id
```

### Risks
```
GET    /api/risks
POST   /api/risks
PUT    /api/risks/:id
DELETE /api/risks/:id
```

### Tasks
```
GET    /api/tasks
POST   /api/tasks
PATCH  /api/tasks/:id
DELETE /api/tasks/:id
```

### Evidence
```
GET    /api/evidence
POST   /api/evidence
DELETE /api/evidence/:id
```

### SOA Controls
```
GET    /api/soa
PUT    /api/soa/:id
```

## Database Setup

Run the SQL schema in Supabase SQL Editor:
```bash
cat schema.sql | psql -h your-db-host -U your-user -d your-database
```

Or paste `schema.sql` contents into Supabase SQL Editor.

## Testing

```bash
# Test health endpoint
curl http://localhost:3001/api/health

# Expected response: {"status":"OK","timestamp":"..."}
```

## Production

For production, consider:
- Add rate limiting
- Add request logging
- Add error tracking (Sentry)
- Use PM2 for process management
- Set up proper SSL/HTTPS