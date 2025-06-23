# Cloudflare L7 Best Practices Repository

A web application built with Cloudflare Workers and Cloudflare D1 that provides a searchable repository of security, performance, and reliability best practices for Cloudflare configurations.

> _**Focused on Layer 7 (L7) Application Services**_

## Features

- 🔍 Search and filter best practices by multiple criteria
- 🏷️ Category and feature-based organization
- 🎯 Detailed configuration examples and expressions
- 📊 Impact and difficulty level indicators
- 🔒 Focus on L7 (application layer) security
- ⚡ Dashboard to add new entries (protected by Cloudflare Access)

## Technology

- **Frontend**: Vanilla JavaScript, HTML, and CSS
- **Backend**: [Cloudflare Workers](https://workers.cloudflare.com/)
- **Database**: [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite)
- **Authentication**: [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/)
- **Initial Data**: Comprehensive SQL file with best practices for various Cloudflare features and configurations [`initial_data.sql`](initial_data.sql)

## Getting Started

1. Clone the repository
2. Deploy to Cloudflare Workers using [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
3. Initialize D1 database using the [`create_d1_schema.sh`](create_d1_schema.sh) script

```bash
chmod +x create_d1_schema.sh
# For remote deployment (default):
./create_d1_schema.sh --remote
# OR for local development:
./create_d1_schema.sh --local
```

Alternatively, already deploy it remotely and then run `npx wrangler dev --remote` to use the remote D1 database.

4. Configure [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/) to protect the `/dashboard` path


## Access Control

The dashboard for adding new entries is protected by Cloudflare Access:

- Public users can view and search best practices
- Authenticated users can access `/dashboard` to add new entries
- Authentication is handled via Cloudflare Access policies (relevant [tutorial](https://developers.cloudflare.com/cloudflare-one/tutorials/extend-sso-with-workers/))

## Data Structure

The repository includes best practices for:

- Categories: `/api/categories`
- Features: `/api/features`

## Contributing

Contributions are welcome! Please feel free to:

1. Submit pull requests with additional best practices or general improvements to this project
2. Use the authenticated dashboard to add new entries (for allowed users only)
3. Suggest improvements to existing content
