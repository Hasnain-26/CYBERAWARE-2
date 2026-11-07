# CyberAware – Streamlit Scam Message Detector

A Streamlit app that sends pasted SMS/email/chat text to an AI model through OpenRouter and displays a scam-risk assessment.

## 1. Get an OpenRouter API key
Create an API key at https://openrouter.ai/keys.

## 2. Run locally
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

Create `.streamlit/secrets.toml`:
```toml
OPENROUTER_API_KEY = "sk-or-v1-your-key-here"
OPENROUTER_MODEL = "openai/gpt-4o-mini"
```

Then run:
```bash
streamlit run app.py
```

You can alternatively paste a key into the sidebar for local testing. Do not commit API keys to GitHub.

## 3. Deploy to Streamlit Community Cloud
1. Create a GitHub repository and upload `app.py`, `requirements.txt`, and `README.md`.
2. Do **not** upload `.streamlit/secrets.toml`.
3. Visit https://share.streamlit.io and choose **Create app**.
4. Select your repository, branch, and `app.py` as the main file.
5. In **Advanced settings → Secrets**, add:
   ```toml
   OPENROUTER_API_KEY = "sk-or-v1-your-key-here"
   OPENROUTER_MODEL = "openai/gpt-4o-mini"
   ```
6. Deploy.

## Notes
- The default model is configurable in the sidebar or through `OPENROUTER_MODEL`.
- Check OpenRouter for the exact model ID and availability in your account.
- The dashboard calculates the spam percentage from SCAM and LIKELY SCAM verdicts in the latest 20 scans. Each message also has an AI-estimated 0–100 spam-risk score. These are indicators, not statistically verified probabilities.
- Recent scan history is kept in Streamlit session state for the active session only; it is not written to a database and may reset when the session ends or the app restarts. Message content is sent to OpenRouter for analysis.
- AI output is advisory, not proof that a message is genuine or fraudulent.
