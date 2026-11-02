# PhishMail — Phishing Email Risk Analyzer

PhishMail is a Streamlit learning project that checks pasted email text or `.txt` / `.eml` files for common phishing warning signs.

## Features
- Rule-based risk score and risk level
- Checks suspicious wording, URLs, sender domains, and mismatched HTML links
- Explains the warning signs that contributed to the score
- Exports scan results to CSV and PDF
- Dark navy/cyan dashboard theme

## Run locally
1. Extract the ZIP file and open the `phishmail_project` folder in VS Code.
2. Install dependencies in the VS Code terminal: `py -m pip install -r requirements.txt`
3. Start the app: `py -m streamlit run app.py`
4. Open the local URL shown in the terminal.

## Important limitation
This is a rule-based educational scanner, not a guarantee that an email is safe or malicious. It can produce false positives or miss threats. Verify senders independently and only analyze messages you are authorized to inspect.
