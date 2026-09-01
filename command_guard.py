import os
import re
import json
import subprocess
from datetime import datetime
from enum import Enum

class RiskLevel(Enum):
    VERT = "VERT"
    ORANGE = "ORANGE"
    ROUGE = "ROUGE"

WHITELIST_VERTE = [
    "ls", "pwd", "whoami", "date", "uptime", "clear",
    "git status", "git log", "git diff", "git branch",
    "cat", "echo", "ps", "df", "free"
]

PATTERNS_ROUGES = [
    r"\brm\b",
    r"\bsudo\b",
    r"\bchmod\b",
    r"\bchown\b",
    r"\bmkfs\b",
    r"\bdd\b",
    r"\bgit push.*--force\b",
    r">",
    r";",
    r"&&",
    r"\|"
]

LOG_DIR = "audit_logs"
LOG_FILE = os.path.join(LOG_DIR, "command_audit.jsonl")


def classify(command: str) -> RiskLevel:
    cmd = command.strip()
    
    for pattern in PATTERNS_ROUGES:
        if re.search(pattern, cmd):
            return RiskLevel.ROUGE

    for prefix in WHITELIST_VERTE:
        if cmd == prefix or cmd.startswith(prefix + " "):
            return RiskLevel.VERT

    return RiskLevel.ORANGE


def log_action(command: str, risk: RiskLevel, executed: bool, output: str = "", error: str = ""):
    """Enregistre chaque tentative dans un journal au format JSONL."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "command": command,
        "risk_level": risk.value,
        "executed": executed,
        "output": output.strip(),
        "error": error.strip()
    }

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")


def run(command: str) -> tuple[bool, str]:
    """
    Exécute une commande système après validation du niveau de risque.
    Retourne un tuple : (succès: bool, sortie/erreur: str)
    """
    cmd = command.strip()
    risk = classify(cmd)

    # 1. Traitement selon le niveau de risque
    if risk == RiskLevel.ROUGE:
        msg = f"[BLOCAGE ROUGE] La commande '{cmd}' est jugée trop dangereuse et a été bloquée."
        print(f"\033[91m{msg}\033[0m")
        log_action(cmd, risk, executed=False, error=msg)
        return False, msg

    elif risk == RiskLevel.ORANGE:
        print(f"\033[93m[ATTENTION ORANGE] La commande '{cmd}' demande une confirmation.\033[0m")
        rep = input("Voulez-vous autoriser cette exécution ? (o/N) : ").strip().lower()
        if rep != 'o':
            msg = "[ANNULÉ] Exécution refusée par l'utilisateur."
            print(msg)
            log_action(cmd, risk, executed=False, error=msg)
            return False, msg

    # 2. Exécution réelle pour VERT ou ORANGE validé
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True
        )
        success = result.returncode == 0
        out = result.stdout if success else result.stderr
        
        log_action(cmd, risk, executed=True, output=result.stdout, error=result.stderr)
        return success, out

    except Exception as e:
        err_msg = f"Erreur d'exécution : {str(e)}"
        log_action(cmd, risk, executed=False, error=err_msg)
        return False, err_msg


# --- Bloc de test de la fonction run() ---
if __name__ == "__main__":
    print("\n--- TEST D'EXÉCUTION RÉELLE (run) ---")
    
    # Test 1 : Commande VERTE (Exécution directe)
    print("\n1. Test commande VERT :")
    ok, stdout = run("pwd")
    print(f"Résultat : {stdout}")

    # Test 2 : Commande ORANGE (Demande de confirmation)
    print("\n2. Test commande ORANGE :")
    ok, stdout = run("mkdir -p test_dir")
    print(f"Succès : {ok}")

    # Test 3 : Commande ROUGE (Blocage strict)
    print("\n3. Test commande ROUGE :")
    ok, stdout = run("rm -rf test_dir")

    # Nettoyage automatique du dossier de test
    if os.path.exists("test_dir"):
        os.rmdir("test_dir")