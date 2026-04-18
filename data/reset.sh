#!/bin/bash
pkill -f "run_all" 2>/dev/null
rm -f honeypotx.db exports/events_export.json
echo '{"cowrie":0, "opencanary":0, "ftp":0}' > state/offsets.json
echo "Reset completato."
