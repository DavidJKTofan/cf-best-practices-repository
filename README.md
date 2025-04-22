# Cloudflare L7 Best Practices Repository

A web application built with Cloudflare Workers and Cloudflare D1 that provides a searchable repository of security, performance, and reliability best practices for Cloudflare configurations.

## Features

- 🔍 Search and filter best practices by multiple criteria
- 🏷️ Category and feature-based organization
- 🎯 Detailed configuration examples and expressions
- 📊 Impact and difficulty level indicators
- 🔒 Focus on L7 (application layer) security

## Technology

- **Frontend**: Vanilla JavaScript, HTML, and CSS
- **Backend**: Cloudflare Workers
- **Database**: Cloudflare D1 (SQLite)
- **Initial Data**: Comprehensive SQL file with best practices for various Cloudflare features and configurations [`initial_data.sql`](initial_data.sql)

## Getting Started

1. Clone the repository
2. Deploy to Cloudflare Workers using [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
3. Initialize D1 database using [`create_d1_schema.sh`](create_d1_schema.sh)

## Data Structure

The repository includes best practices for:
- DNS and SSL/TLS configuration
- WAF (Managed and Custom Rules)
- Bot Management
- Rate Limiting
- API Security
- Origin Protection
- Performance Optimization
- And more...

## Contributing

Contributions are welcome! Please feel free to submit pull requests with additional best practices or improvements.