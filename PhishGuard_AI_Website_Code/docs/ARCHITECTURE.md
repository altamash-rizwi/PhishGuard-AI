# Architecture

## Current MVP

```text
Browser
  -> Flask routes and server-rendered templates
      -> URL normalization and feature extraction
      -> heuristic rule scoring + optional approved ML candidate inference
      -> SQLite: scans, users, reports, report reviews, lessons, quiz attempts, audit logs
      -> optional DNS resolution / WHOIS lookup (never fetches submitted page)
```

## Target scalable architecture from the product design

```text
Next.js/TypeScript client over HTTPS
  -> API gateway / reverse proxy
  -> versioned application API (FastAPI or NestJS)
  -> isolated detection service (features, rules, validated ML, reputation integrations)
  -> queue workers for asynchronous scans
  -> PostgreSQL + Redis + object storage
  -> logs, metrics, traces and alerts
```

The scalable architecture is a future design, not a claim about the current implementation. Start with the Flask MVP for the college project, then migrate to the target architecture only when there is a concrete scaling need.
