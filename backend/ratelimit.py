"""Rate limiter in memoria per proteggere /auth/login.

Traccia i tentativi falliti per chiave (IP) in una finestra temporale scorrevole.
Superata la soglia, la chiave e' bloccata finche' i tentativi vecchi non escono
dalla finestra. Blocca due minacce insieme:
- brute force delle credenziali;
- DoS di CPU: authenticate() esegue PBKDF2 a 200k iterazioni, quindi il blocco
  scatta *prima* dell'hashing, evitando che login ripetuti saturino la CPU.

Solo stdlib, thread-safe (l'API FastAPI serve gli endpoint sync in threadpool).
"""
import time
from threading import Lock
from typing import Dict, List


class RateLimiter:
    def __init__(
        self,
        max_attempts: int = 10,
        window_seconds: int = 300,
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._fails: Dict[str, List[float]] = {}
        self._lock = Lock()
        self._last_sweep = 0.0

    def _sweep(self, now: float) -> None:
        """Pulizia globale al piu una volta per finestra (chiamare sotto lock).

        _prune agisce solo sulla chiave interrogata: senza sweep, gli IP che
        falliscono e non tornano piu resterebbero in memoria per sempre.
        """
        if now - self._last_sweep < self.window_seconds:
            return
        self._last_sweep = now
        cutoff = now - self.window_seconds
        for key in list(self._fails):
            kept = [ts for ts in self._fails[key] if ts >= cutoff]
            if kept:
                self._fails[key] = kept
            else:
                del self._fails[key]

    def _prune(self, key: str, now: float) -> List[float]:
        cutoff = now - self.window_seconds
        kept = [ts for ts in self._fails.get(key, []) if ts >= cutoff]
        if kept:
            self._fails[key] = kept
        else:
            self._fails.pop(key, None)
        return kept

    def is_locked(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            return len(self._prune(key, now)) >= self.max_attempts

    def record_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            self._sweep(now)
            history = self._prune(key, now)
            history.append(now)
            self._fails[key] = history

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)
