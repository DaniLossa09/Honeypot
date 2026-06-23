#!/usr/bin/env python3
"""Genera l'ambiente-scenografia (fake corporate) che un attaccante vede.

Produce la scenografia su tre canali, in modo coerente tra loro:
  1. honeypots/fake_corp/ftp_root          -> contenuti serviti da dionaea (FTP)
  2. honeypots/cowrie/honeyfs              -> contenuti leggibili via `cat` in SSH/Telnet
  3. honeypots/cowrie/share/cowrie/fs.pickle -> struttura mostrata da `ls` (dalla honeyfs)

Aggiorna inoltre cowrie/userdb.txt (utenti fake) e, salvo opt-out, applica i
mount honeyfs/pickle in docker-compose.yml e la sezione [shell] in cowrie.cfg.

IMPORTANTE: nessun dato generato qui finisce nei log/DB reali o nella dashboard.
E' solo scenografia per ingannare l'attaccante; la pipeline di rilevazione resta
intatta. Lo script NON tocca data/, honeypots/logs/ e non fa chown.

Solo stdlib (ARM64-safe). Contenuti in italiano.
"""
import argparse
import pickle
import random
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
HONEYPOTS_DIR = ROOT_DIR / "honeypots"
DEFAULT_FTP_OUTPUT = HONEYPOTS_DIR / "fake_corp"
DEFAULT_HONEYFS = HONEYPOTS_DIR / "cowrie" / "honeyfs"
DEFAULT_PICKLE = HONEYPOTS_DIR / "cowrie" / "share" / "cowrie" / "fs.pickle"
USERDB_PATH = HONEYPOTS_DIR / "cowrie" / "userdb.txt"
COMPOSE_PATH = HONEYPOTS_DIR / "docker-compose.yml"
COWRIE_CFG_PATH = HONEYPOTS_DIR / "cowrie" / "cowrie.cfg"

# --- Formato fs di Cowrie (cowrie/shell/fs.py) -----------------------------
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = range(7)
DIR_MODE = 0o40755
FILE_MODE = 0o100644
EXE_MODE = 0o100755
# ctime fisso e plausibile: i file non devono sembrare creati "adesso".
FIXED_CTIME = int(datetime(2026, 1, 15, 9, 0, tzinfo=timezone.utc).timestamp())
# Protocollo 2: leggibile da qualunque Python 3 dell'immagine cowrie.
PICKLE_PROTOCOL = 2

# --- Pool dati --------------------------------------------------------------
FIRST_NAMES = [
    "marco", "luca", "giulia", "andrea", "francesca", "paolo", "elena",
    "stefano", "laura", "matteo", "anna", "roberto", "chiara", "davide",
    "sara", "alessandro", "valentina", "simone", "martina", "federico",
]
LAST_NAMES = [
    "rossi", "bianchi", "romano", "conti", "gallo", "ferrari", "ricci",
    "marino", "greco", "bruno", "rinaldi", "costa", "moretti", "lombardi",
    "barbieri", "fontana", "santoro", "mariani", "rizzo", "caruso",
]
DEPARTMENTS = ["IT", "Finance", "HR", "DevOps", "Sales", "Security", "Legal"]
DEPT_ROLE = {
    "IT": "sysadmin",
    "Finance": "finance-ops",
    "HR": "hr-operator",
    "DevOps": "deploy",
    "Sales": "crm-user",
    "Security": "soc-analyst",
    "Legal": "legal-clerk",
}
PASSWORD_PATTERNS = [
    "Winter2026!", "Spring2026!", "Backup2026!", "Welcome2026!",
    "Company2026!", "Password2026!", "ChangeMe2026!", "Vpn2026!",
]

# densita -> quantita concrete
DENSITY = {
    "basso": {"users": 5, "homes": 2, "depts": 3, "docs": (1, 2), "breadcrumbs": 2, "logs": 20},
    "medio": {"users": 14, "homes": 5, "depts": 5, "docs": (3, 4), "breadcrumbs": 4, "logs": 80},
    "alto": {"users": 30, "homes": 10, "depts": 7, "docs": (6, 8), "breadcrumbs": 7, "logs": 200},
}

# Flavor leggero per settore: nome app in /opt, sottocartella documenti in home,
# e un paio di file/cartella a tema sotto /srv.
SECTORS = {
    "generico": {"label": "Generico", "app": "gestionale", "home_dir": "documenti",
                 "srv": [("archivio/README.txt", "Archivio documentale {company}.\nAccesso riservato.\n")]},
    "it": {"label": "IT / Software", "app": "ci-runner", "home_dir": "progetti",
           "srv": [("repos/README.txt", "Mirror interni dei repository {company}.\n"),
                   ("repos/deploy.sh", "#!/bin/bash\n# deploy {company} - non eseguire in prod\nssh deploy@db-prod-01.internal\n")]},
    "manifatturiero": {"label": "Manifatturiero", "app": "mes", "home_dir": "produzione",
                       "srv": [("produzione/ordini_produzione.csv", "ordine,prodotto,quantita,stato\nOP-1042,valvola-X,500,in corso\n"),
                               ("produzione/distinta_base.csv", "componente,fornitore,costo\nacciaio-304,MetalSud,12.40\n")]},
    "finance": {"label": "Finance / Banking", "app": "core-banking", "home_dir": "pratiche",
                "srv": [("pratiche/conti_correnti.csv", "iban,intestatario,saldo\nIT60X0542811101000000123456,Cliente SpA,184220.50\n"),
                        ("pratiche/bonifici_sospesi.csv", "data,beneficiario,importo,stato\n2026-01-16,Northwind,9280.00,pending\n")]},
    "healthcare": {"label": "Healthcare", "app": "cartelle-cliniche", "home_dir": "referti",
                   "srv": [("cartelle/pazienti.csv", "id,nome,reparto,diagnosi\nP-0091,M. Rossi,cardiologia,riservato\n"),
                           ("cartelle/turni_medici.csv", "medico,reparto,turno\ndott.ssa Conti,radiologia,notte\n")]},
    "logistica": {"label": "Logistica", "app": "wms", "home_dir": "spedizioni",
                  "srv": [("spedizioni/tracking.csv", "spedizione,destinazione,stato\nSP-7781,Milano,in transito\n"),
                          ("spedizioni/flotta.csv", "mezzo,targa,autista\nfurgone-12,AB123CD,M. Greco\n")]},
    "retail": {"label": "Retail / E-commerce", "app": "ecommerce", "home_dir": "ordini",
               "srv": [("shop/ordini.csv", "ordine,cliente,totale,stato\nORD-5521,cliente@example.com,249.90,pagato\n"),
                       ("shop/listino.csv", "sku,prodotto,prezzo\nSKU-001,prodotto base,19.90\n")]},
    "energia": {"label": "Energia / Utility", "app": "scada-gateway", "home_dir": "impianti",
                "srv": [("impianti/letture_contatori.csv", "contatore,zona,kwh\nCNT-0042,nord,18420\n"),
                        ("impianti/allarmi_scada.log", "2026-01-15 03:12 WARN soglia superata cabina-7\n")]},
}


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S")


def safe_write(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


# --- Utenti -----------------------------------------------------------------
def generate_users(company: str, count: int, depts: int) -> list[dict]:
    active_depts = DEPARTMENTS[:depts]
    domain = company.lower().replace(" ", "")
    users: list[dict] = []
    used: set[str] = set()
    for _ in range(count):
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        username = f"{first}.{last}"
        while username in used:
            username = f"{first}.{last}{random.randint(2, 99)}"
        used.add(username)
        department = random.choice(active_depts)
        users.append({
            "username": username,
            "password": random.choice(PASSWORD_PATTERNS),
            "department": department,
            "role": DEPT_ROLE[department],
            "email": f"{username}@{domain}.local",
        })
    users.extend([
        {"username": "svc-backup", "password": "Backup2026!", "department": "IT",
         "role": "service-account", "email": f"svc-backup@{domain}.local"},
        {"username": "deploy", "password": "Deploy2026!", "department": "DevOps",
         "role": "deployment-account", "email": f"deploy@{domain}.local"},
    ])
    return users


def render_userdb(users: list[dict]) -> str:
    lines = [
        "# BEGIN HONEYPOTX FAKE CORPORATE USERS",
        "# Generated by scripts/generate_fake_corp.py",
    ]
    lines.extend(f"{u['username']}:x:{u['password']}" for u in users)
    lines.append("# END HONEYPOTX FAKE CORPORATE USERS")
    return "\n".join(lines) + "\n"


def update_cowrie_userdb(users: list[dict]) -> None:
    if USERDB_PATH.exists():
        shutil.copy2(USERDB_PATH, USERDB_PATH.with_name(f"userdb.txt.backup.{now_stamp()}"))
        current = USERDB_PATH.read_text(encoding="utf-8")
    else:
        current = ""
    start = "# BEGIN HONEYPOTX FAKE CORPORATE USERS"
    end = "# END HONEYPOTX FAKE CORPORATE USERS"
    generated = render_userdb(users)
    if start in current and end in current:
        before = current.split(start, 1)[0].rstrip()
        after = current.split(end, 1)[1].lstrip()
        content = "\n".join(p for p in [before, generated.rstrip(), after.rstrip()] if p) + "\n"
    else:
        content = current.rstrip() + "\n\n" + generated if current.strip() else generated
    USERDB_PATH.write_text(content, encoding="utf-8")


# --- Contenuti documenti ----------------------------------------------------
DEPT_DOCS = {
    "IT": ["inventario_server.csv", "credenziali_switch.txt", "procedura_backup.md", "rete_vlan.conf"],
    "Finance": ["bilancio_2026.csv", "fatture_da_pagare.csv", "conti_bancari.txt", "budget_reparti.csv"],
    "HR": ["dipendenti.csv", "stipendi.csv", "colloqui.md", "policy_ferie.txt"],
    "DevOps": ["pipeline.yml", "deploy_notes.txt", "secrets.env", "runbook.md"],
    "Sales": ["clienti.csv", "offerte.csv", "provvigioni.txt", "crm_export.csv"],
    "Security": ["incidenti.md", "regole_firewall.conf", "note_soc.txt", "vulnerabilita.csv"],
    "Legal": ["contratti.csv", "nda_fornitori.txt", "gdpr_registro.csv", "policy.md"],
}


def doc_content(dept: str, filename: str, company: str, users: list[dict]) -> str:
    sample = users[:8]
    if filename == "credenziali_switch.txt":
        return (f"# Credenziali apparati di rete {company}\n"
                "core-sw-01  admin / Sw1tchCore2026!\n"
                "fw-perimetro root / Firewall2026!\n"
                "ricordarsi di ruotare dopo l'audit\n")
    if filename == "conti_bancari.txt":
        return (f"Conti societari {company}\n"
                "IBAN principale: IT60X0542811101000000123456\n"
                "Home banking: tesoreria / Banca2026!\n")
    if filename == "secrets.env":
        return ("APP_ENV=production\nDB_HOST=db-prod-01.internal\nDB_USER=deploy\n"
                "DB_PASS=Deploy2026!\nJWT_SECRET=prod-7f3a9c21\nS3_BUCKET=corp-prod-backups\n")
    if filename in ("dipendenti.csv", "crm_export.csv", "clienti.csv"):
        rows = "\n".join(f"{u['username']},{u['email']},{u['department']}" for u in sample)
        return "username,email,reparto\n" + rows + "\n"
    if filename == "stipendi.csv":
        rows = "\n".join(f"{u['username']},{random.randint(28, 65)}000" for u in sample)
        return "dipendente,ral_annua\n" + rows + "\n"
    if filename.endswith(".md"):
        return f"# {filename[:-3].replace('_', ' ').title()} - {dept}\n\nNote interne {company}.\nDocumento riservato.\n"
    if filename.endswith((".conf", ".yml")):
        return f"# {filename} ({dept}) - {company}\nenv: production\nowner: {dept.lower()}-team\n"
    if filename.endswith(".csv"):
        return f"voce,valore,reparto\nesempio,1234,{dept}\n"
    return f"Documento interno {dept} - {company}.\nRiservato, non diffondere.\n"


# --- honeyfs (sessione SSH/Telnet) -----------------------------------------
def build_honeyfs(honeyfs: Path, company: str, sector: str, users: list[dict],
                  params: dict) -> None:
    if honeyfs.exists():
        shutil.move(str(honeyfs), str(honeyfs.with_name(f"honeyfs.backup.{now_stamp()}")))
    honeyfs.mkdir(parents=True, exist_ok=True)

    sec = SECTORS.get(sector, SECTORS["generico"])
    domain = company.lower().replace(" ", "")
    human_users = [u for u in users if u["role"] not in ("service-account", "deployment-account")]

    # /etc
    safe_write(honeyfs / "etc/hostname", "server01\n")
    safe_write(honeyfs / "etc/issue", f"{company} - Sistema riservato. Accessi monitorati.\n\n")
    safe_write(honeyfs / "etc/motd",
               f"\n  Benvenuto su server01 ({company})\n  Uso autorizzato esclusivamente al personale interno.\n\n")
    safe_write(honeyfs / "etc/os-release",
               'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\n'
               'VERSION_ID="12"\nID=debian\n')
    passwd = ["root:x:0:0:root:/root:/bin/bash",
              "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
              "svc-backup:x:990:990:Backup Service:/var/lib/backup:/bin/bash"]
    for i, u in enumerate(human_users):
        uid = 1000 + i
        passwd.append(f"{u['username']}:x:{uid}:{uid}:{u['username']}:/home/{u['username']}:/bin/bash")
    safe_write(honeyfs / "etc/passwd", "\n".join(passwd) + "\n")

    # /proc minimale (uname/cat plausibili)
    safe_write(honeyfs / "proc/version",
               "Linux version 6.1.0-18-arm64 (debian@debian) (gcc 12.2.0) #1 SMP Debian\n")
    safe_write(honeyfs / "proc/cpuinfo",
               "processor\t: 0\nmodel name\t: ARMv8 Processor rev 3\nHardware\t: BCM2835\n")
    safe_write(honeyfs / "proc/meminfo", "MemTotal:        3882436 kB\nMemFree:          204880 kB\n")

    # /root (esche ad alto valore)
    safe_write(honeyfs / "root/.bash_history",
               "ls -la\ncat /etc/passwd\nmysql -u root -p'Db2026!' -e 'show databases;'\n"
               "scp /var/backups/db-prod.sql.gz svc-backup@nas-01.internal:/backups/\n"
               "cat /root/credenziali.txt\nvpn-connect --user deploy\nhistory -c\n")
    safe_write(honeyfs / "root/credenziali.txt",
               f"# Credenziali amministrative {company} (NON committare)\n"
               "root@db-prod-01: Db2026!\n"
               "nas-01 (svc-backup): Backup2026!\n"
               "vpn gateway: deploy / Deploy2026!\n")
    safe_write(honeyfs / "root/note.txt",
               "TODO: ruotare le password dopo la migrazione.\n"
               "Il pannello admin legacy e' ancora su http://10.0.0.5/admin\n")

    # /var/www (web app esca)
    safe_write(honeyfs / "var/www/html/index.html",
               f"<!doctype html><html><head><title>{company}</title></head>"
               f"<body><h1>{company} - Intranet</h1></body></html>\n")
    safe_write(honeyfs / "var/www/html/config.php",
               "<?php\n$DB_HOST='db-prod-01.internal';\n$DB_USER='webapp';\n"
               "$DB_PASS='Web2026!';\n$DB_NAME='intranet';\n")

    # /var/backups (esca)
    safe_write(honeyfs / "var/backups/db-prod.sql.gz",
               "-- dump compresso (placeholder)\n-- contiene tabelle users, payments, sessions\n")
    safe_write(honeyfs / "var/backups/users.sql",
               "INSERT INTO users(user,pass) VALUES\n"
               + ",\n".join(f"('{u['username']}','{u['password']}')" for u in human_users[:10]) + ";\n")

    # /opt/<app> a tema settore
    app = sec["app"]
    safe_write(honeyfs / f"opt/{app}/README.md",
               f"# {app} ({sec['label']})\n\nApplicazione interna {company}.\n")
    safe_write(honeyfs / f"opt/{app}/.env",
               f"APP={app}\nENV=production\nADMIN_USER=admin\nADMIN_PASS=Admin2026!\n")

    # /srv a tema settore
    for rel, tpl in sec["srv"]:
        content = tpl.format(company=company)
        mode = EXE_MODE if rel.endswith(".sh") else 0o644
        safe_write(honeyfs / "srv" / rel, content, mode=mode)

    # /var/log (rumore credibile, scala con densita)
    auth_lines = []
    for _ in range(params["logs"]):
        u = random.choice(human_users)
        auth_lines.append(f"Jan 15 0{random.randint(0,9)}:{random.randint(10,59)}:00 server01 "
                          f"sshd[{random.randint(1000,9999)}]: Accepted password for {u['username']} "
                          f"from 10.0.0.{random.randint(2,254)} port {random.randint(40000,60000)} ssh2")
    safe_write(honeyfs / "var/log/auth.log", "\n".join(auth_lines) + "\n")

    # /home/<user> popolate (scala con densita), con documenti del reparto
    lo, hi = params["docs"]
    for u in human_users[:params["homes"]]:
        home = honeyfs / "home" / u["username"]
        safe_write(home / ".bash_history",
                   "ls\ncat ~/.ssh/id_rsa\nssh deploy@db-prod-01.internal\nsudo -l\n")
        safe_write(home / ".ssh/known_hosts",
                   "db-prod-01.internal ssh-rsa AAAAB3Nza...troncato\n")
        docs_dir = home / sec["home_dir"]
        pool = DEPT_DOCS.get(u["department"], DEPT_DOCS["IT"])
        chosen = random.sample(pool, min(random.randint(lo, hi), len(pool)))
        for fname in chosen:
            safe_write(docs_dir / fname, doc_content(u["department"], fname, company, users))


# --- fs.pickle (cosa mostra `ls`) ------------------------------------------
def _node_from_path(path: Path) -> list:
    name = path.name
    if path.is_dir():
        children = [_node_from_path(c) for c in
                    sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name))]
        return [name, T_DIR, 0, 0, 4096, DIR_MODE, FIXED_CTIME, children, None, None]
    size = path.stat().st_size
    mode = EXE_MODE if path.suffix == ".sh" else FILE_MODE
    return [name, T_FILE, 0, 0, size, mode, FIXED_CTIME, [], None, None]


def build_fs_pickle(honeyfs: Path, out: Path) -> None:
    if out.exists():
        shutil.copy2(out, out.with_name(f"{out.name}.backup.{now_stamp()}"))
    root = ["/", T_DIR, 0, 0, 4096, DIR_MODE, FIXED_CTIME, [], None, None]
    root[A_CONTENTS] = [_node_from_path(c) for c in
                        sorted(honeyfs.iterdir(), key=lambda p: (p.is_file(), p.name))]
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "wb") as fh:
        pickle.dump(root, fh, protocol=PICKLE_PROTOCOL)
    out.chmod(0o644)


# --- FTP root (dionaea) -----------------------------------------------------
def generate_ftp_root(output: Path, company: str, sector: str, users: list[dict],
                      params: dict) -> None:
    ftp = output / "ftp_root"
    if ftp.exists():
        shutil.rmtree(ftp)
    sec = SECTORS.get(sector, SECTORS["generico"])
    human = [u for u in users if u["role"] not in ("service-account", "deployment-account")]
    n = max(5, params["users"])
    safe_write(ftp / "README.txt", f"{company} internal file server\nSolo personale autorizzato.\n")
    safe_write(ftp / "IT" / "backup" / "backup-prod.env",
               "APP_ENV=production\nDB_HOST=db-prod-01.internal\nDB_USER=svc-backup\n"
               "DB_PASS=Backup2026!\nS3_BUCKET=corp-prod-backups\n")
    safe_write(ftp / "IT" / "vpn" / "vpn-users.csv",
               "username,department,status\n"
               + "\n".join(f"{u['username']},{u['department']},active" for u in human[:n]) + "\n")
    safe_write(ftp / "Finance" / "Q4" / "wire-transfers.csv",
               "date,vendor,amount,status\n2026-01-12,ACME Hosting,18420.50,pending\n"
               "2026-01-16,Northwind Security,9280.00,approved\n")
    safe_write(ftp / "HR" / "employees.csv",
               "name,email,department,role\n"
               + "\n".join(f"{u['username']},{u['email']},{u['department']},{u['role']}" for u in users) + "\n")
    if params["depts"] >= 4:
        safe_write(ftp / "DevOps" / "deploy" / "deploy_notes.txt",
                   "Deployment notes\n- legacy admin panel: /admin\n- deploy user: deploy\n"
                   "- rotate Deploy2026! after migration\n")
    if params["depts"] >= 6:
        safe_write(ftp / "Security" / "alerts" / "false_positive_notes.md",
                   "# SOC notes\n- Investigate repeated login attempts against svc-backup\n"
                   "- Monitor SQLi probes on /search and /login\n")
    # file a tema settore
    for rel, tpl in sec["srv"]:
        safe_write(ftp / sec["label"].split()[0] / Path(rel).name, tpl.format(company=company))


def write_manifest(output: Path, company: str, sector: str, density: str,
                   users: list[dict]) -> None:
    manifest = {
        "company": company,
        "sector": sector,
        "density": density,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "users": users,
        "notes": "Dati interamente fittizi, a solo scopo di inganno/honeypot.",
    }
    import json
    safe_write(output / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")


# --- Patch compose / cfg ----------------------------------------------------
def patch_compose() -> bool:
    if not COMPOSE_PATH.exists():
        return False
    text = COMPOSE_PATH.read_text(encoding="utf-8")
    honeyfs_mount = "- ./cowrie/honeyfs:/cowrie/cowrie-git/honeyfs:ro"
    pickle_mount = "- ./cowrie/share/cowrie/fs.pickle:/cowrie/cowrie-git/share/cowrie/fs.pickle:ro"
    if honeyfs_mount in text and pickle_mount in text:
        return False
    shutil.copy2(COMPOSE_PATH, COMPOSE_PATH.with_name(f"docker-compose.yml.backup.{now_stamp()}"))
    anchor = "./cowrie/userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro"
    out_lines: list[str] = []
    inserted = False
    for line in text.splitlines():
        out_lines.append(line)
        if not inserted and anchor in line:
            indent = line[: len(line) - len(line.lstrip())]
            if honeyfs_mount not in text:
                out_lines.append(f"{indent}{honeyfs_mount}")
            if pickle_mount not in text:
                out_lines.append(f"{indent}{pickle_mount}")
            inserted = True
    COMPOSE_PATH.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    return inserted


def patch_cowrie_cfg() -> bool:
    if not COWRIE_CFG_PATH.exists():
        return False
    text = COWRIE_CFG_PATH.read_text(encoding="utf-8")
    if "[shell]" in text:
        return False
    shutil.copy2(COWRIE_CFG_PATH, COWRIE_CFG_PATH.with_name(f"cowrie.cfg.backup.{now_stamp()}"))
    block = "\n[shell]\nfilesystem = share/cowrie/fs.pickle\ncontents_path = honeyfs\n"
    COWRIE_CFG_PATH.write_text(text.rstrip() + "\n" + block, encoding="utf-8")
    return True


# --- Input interattivo ------------------------------------------------------
def ask_text(prompt: str, default: str) -> str:
    if not sys.stdin.isatty():
        return default
    resp = input(f"{prompt} [{default}]: ").strip()
    return resp or default


def ask_choice(prompt: str, options: list[str], default: str) -> str:
    if not sys.stdin.isatty():
        return default
    print(f"{prompt}")
    for i, opt in enumerate(options, 1):
        mark = " (default)" if opt == default else ""
        print(f"  {i}) {opt}{mark}")
    resp = input("Scelta [numero o nome]: ").strip().lower()
    if not resp:
        return default
    if resp.isdigit() and 1 <= int(resp) <= len(options):
        return options[int(resp) - 1]
    return resp if resp in options else default


def resolve_params(args) -> tuple[str, str, str]:
    company = args.company if args.company is not None else ask_text("Nome azienda", "ACME Corp")
    sector = args.sector if args.sector is not None else ask_choice(
        "Settore/attivita", list(SECTORS.keys()), "generico")
    if sector not in SECTORS:
        sector = "generico"
    density = args.density if args.density is not None else ask_choice(
        "Densita generazione", list(DENSITY.keys()), "medio")
    if density not in DENSITY:
        density = "medio"
    return company, sector, density


def main() -> int:
    parser = argparse.ArgumentParser(description="Genera la scenografia fake corporate (Cowrie + FTP).")
    parser.add_argument("--company", default=None, help="Nome azienda fittizia")
    parser.add_argument("--sector", default=None, choices=list(SECTORS.keys()), help="Settore/attivita")
    parser.add_argument("--density", default=None, choices=list(DENSITY.keys()), help="basso|medio|alto")
    parser.add_argument("--users", type=int, default=None, help="Override numero utenti umani")
    parser.add_argument("--seed", type=int, default=None, help="Seed deterministico")
    parser.add_argument("--output", type=Path, default=DEFAULT_FTP_OUTPUT, help="Dir fake_corp (FTP)")
    parser.add_argument("--honeyfs", type=Path, default=DEFAULT_HONEYFS, help="Dir honeyfs Cowrie")
    parser.add_argument("--pickle", type=Path, default=DEFAULT_PICKLE, help="Path fs.pickle")
    parser.add_argument("--no-userdb", action="store_true", help="Non aggiornare userdb.txt")
    parser.add_argument("--no-honeyfs", action="store_true", help="Non generare honeyfs/pickle")
    parser.add_argument("--no-pickle", action="store_true", help="Genera honeyfs ma non il pickle")
    parser.add_argument("--no-compose", action="store_true", help="Non modificare compose/cfg")
    parser.add_argument("--non-interactive", action="store_true", help="Nessun prompt (usa default/flag)")
    args = parser.parse_args()

    if args.non_interactive:
        sys.stdin = open("/dev/null")  # disabilita i prompt isatty

    if args.seed is not None:
        random.seed(args.seed)

    company, sector, density = resolve_params(args)
    params = dict(DENSITY[density])
    if args.users is not None:
        params["users"] = max(1, min(args.users, 100))

    users = generate_users(company, params["users"], params["depts"])

    generate_ftp_root(args.output, company, sector, users, params)
    write_manifest(args.output, company, sector, density, users)
    if not args.no_userdb:
        update_cowrie_userdb(users)

    honeyfs_done = pickle_done = False
    if not args.no_honeyfs:
        build_honeyfs(args.honeyfs, company, sector, users, params)
        honeyfs_done = True
        if not args.no_pickle:
            build_fs_pickle(args.honeyfs, args.pickle)
            pickle_done = True

    compose_patched = cfg_patched = False
    if not args.no_compose:
        compose_patched = patch_compose()
        cfg_patched = patch_cowrie_cfg()

    print("\n=== Scenografia generata ===")
    print(f"  Azienda : {company}")
    print(f"  Settore : {SECTORS[sector]['label']} ({sector})")
    print(f"  Densita : {density}  -> {params['users']} utenti, {params['homes']} home popolate")
    print(f"  FTP root: {args.output / 'ftp_root'}")
    if honeyfs_done:
        print(f"  honeyfs : {args.honeyfs}")
    if pickle_done:
        print(f"  fs.pickle: {args.pickle}")
    if not args.no_userdb:
        print(f"  userdb  : {USERDB_PATH} (aggiornato, con backup)")
    if compose_patched:
        print("  compose : mount honeyfs/pickle aggiunti (backup creato)")
    if cfg_patched:
        print("  cowrie.cfg: sezione [shell] aggiunta (backup creato)")
    print("\nPer applicare in Cowrie:")
    print("  docker compose -f honeypots/docker-compose.yml up -d cowrie")
    print("  (oppure: docker restart cowrie)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
