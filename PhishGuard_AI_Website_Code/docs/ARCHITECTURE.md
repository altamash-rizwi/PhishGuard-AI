# PhishGuard AI Architecture

User
  ↓
Web UI (HTML/CSS)
  ↓
Flask `/scan`
  ↓
URL validation
  ↓
Feature extraction
  ├─ URL length
  ├─ HTTPS
  ├─ domain/IP indicators
  ├─ dots/hyphens/subdomains
  ├─ suspicious tokens
  └─ path/query characteristics
  ↓
TF-IDF character representation
  ↓
Random Forest classifier
  ↓
Preliminary classification + confidence
  ↓
Optional WHOIS/domain context
  ↓
Result page + security recommendations
  ↓
SQLite scan history
