"""
run_all.py
==========
Esegue la pipeline completa di HoneypotX in ordine:

  1. Legge i log di Cowrie, OpenCanary, Dionaea
  2. Classifica e geolocalizza gli attacchi  (analyzer.py)
  3. Genera spiegazioni AI in italiano       (ai_explainer.py)
  4. Stampa il report educativo finale

Esegui con:
    python run_all.py
"""

from analyzer    import analyze_all, print_stats, export_json
from ai_explainer import explain_all_attacks, print_explanations_report, export_explanations_json

print("╔══════════════════════════════════════════╗")
print("║      HoneypotX — Pipeline Completa      ║")
print("╚══════════════════════════════════════════╝\n")

print("─── STEP 1: Analisi log honeypot ───────────\n")
analyze_all()
print_stats()
export_json()

print("\n─── STEP 2: Spiegazioni AI ─────────────────\n")
explain_all_attacks()
print_explanations_report()
export_explanations_json()

print("\n✅ Pipeline completata!")
print("   File prodotti:")
print("   → honeypot_data.db        (tutti gli eventi)")
print("   → events_export.json      (eventi per dashboard)")
print("   → explanations.db         (spiegazioni AI)")
print("   → explanations_export.json (spiegazioni per dashboard)")
