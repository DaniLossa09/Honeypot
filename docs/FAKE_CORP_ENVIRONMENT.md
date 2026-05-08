# Fake Corporate Environment Generator

Il generatore crea un ambiente aziendale fittizio per rendere gli honeypot piu credibili.

Script:

```bash
python3 scripts/generate_fake_corp.py
```

Output principale:

```text
honeypots/fake_corp/
```

Contenuti generati:

- utenti aziendali fittizi;
- credenziali esca;
- cartelle IT, HR, Finance, DevOps, Security;
- file finti come `.env`, CSV dipendenti, note deploy, backup e VPN users;
- manifest JSON con utenti e breadcrumb generati.

## Cowrie

Lo script aggiorna:

```text
honeypots/cowrie/userdb.txt
```

Gli utenti generati vengono inseriti tra marker:

```text
# BEGIN HONEYPOTX FAKE CORPORATE USERS
# END HONEYPOTX FAKE CORPORATE USERS
```

Prima di aggiornare il file viene creata una copia backup.

## FTP

Lo script crea una root fake:

```text
honeypots/fake_corp/ftp_root
```

Il container FTP monta questa directory in sola lettura:

```text
/opt/dionaea/fake_corp/ftp_root
```

Il servizio FTP puo rispondere a:

- `PWD`
- `CWD`
- `LIST`
- `RETR`

I comandi vengono sempre loggati in `ftp.json`, quindi la dashboard puo mostrare esplorazioni, download e tentativi operativi.

## Esempi

Generazione standard:

```bash
python3 scripts/generate_fake_corp.py
```

Generazione con nome azienda:

```bash
python3 scripts/generate_fake_corp.py --company "Acme Manufacturing"
```

Generazione deterministica:

```bash
python3 scripts/generate_fake_corp.py --seed 42
```

Generazione senza modificare Cowrie userdb:

```bash
python3 scripts/generate_fake_corp.py --no-userdb
```

## Dopo la generazione

Riavvia gli honeypot Docker per montare i nuovi asset:

```bash
docker compose -f honeypots/docker-compose.yml up -d --build
```

Oppure riavvia solo FTP/Cowrie se necessario.
