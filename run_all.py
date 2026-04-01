"""
run_all.py
==========
Esegue la pipeline completa di HoneypotX in ordine.
"""

import os
from dotenv import load_dotenv

# Carica il .env subito, così si propaga ai sottomoduli
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

from backend.analyzer import analyze_all, print_stats, export_json
from backend.ai_explainer import explain_all_attacks, print_explanations_report, export_explanations_json

def main():
    print("╔══════════════════════════════════════════╗")
    print("║      HoneypotX — Pipeline Completa       ║")
    print("╚══════════════════════════════════════════╝\n")
    
    print("─── STEP 1: Analisi log honeypot ───────────\n")
    analyze_all()
    print_stats()
    export_json()
    
    print("\n─── STEP 2: Spiegazioni AI ─────────────────\n")
    explain_all_attacks()
    print_explanations_report()
    export_explanations_json()
    
    print("\n✅ Pipeline completata! I file sono generati nella cartella /data/")

if __name__ == '__main__':
    main()