# Standalone Local Setup (Single Player)

This is the standalone version of the challenge for individual practice without the multi-team spawner or scoreboard.

## Prerequisites
- Docker & Docker Compose
- A free Groq, Cerebras, or Gemini API key

## Setup
1. Set your API key in `chains.py` or export `LLM_API_KEY`.
2. Start the container:
   ```bash
   docker compose up --build
   ```
3. Open http://localhost:8001 in your browser.

## Flags
Flags in this standalone build are deterministic and match the techniques in root `WRITEUP.md`.
