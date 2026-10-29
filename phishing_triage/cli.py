"""Command-line interface: python -m phishing_triage.cli samples/suspicious_login.eml"""
import argparse
import json
from pathlib import Path
from .analyzer import analyze_file

def main():
    parser = argparse.ArgumentParser(description='Offline phishing email triage')
    parser.add_argument('email', help='Path to .eml file')
    parser.add_argument('--output', help='Optional JSON output path')
    args = parser.parse_args()
    try:
        report = analyze_file(args.email)
        rendered = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            target = Path(args.output)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(rendered + '\n', encoding='utf-8')
            print(f'Report saved to {target}')
        else:
            print(rendered)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Error: {exc}\n')

if __name__ == '__main__':
    main()
