# GA5 incident agent
Zero-dependency Node 20+ service. Env vars:
- LLM_API_KEY (required), LLM_BASE_URL (any OpenAI-compatible /chat/completions), LLM_MODEL
  - Gemini free tier: LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai  LLM_MODEL=gemini-2.0-flash
  - Groq: https://api.groq.com/openai/v1   OpenAI: gpt-4o-mini (default)
- PORT (default 8080), DATA_DIR (must be a persistent disk/volume)
Deploy on any host with HTTPS + persistent disk (Render, Fly.io, Railway, VPS behind Caddy). Submit the bare https://host URL.
Run one instance only (state is local files). `npm test` runs a mock-model end-to-end test.
