"""Run by entrypoint.sh at every container start.

Takes the base flags from flag_config.py (kept as flag_config_base.py) and appends a short hash of
FLAG_SECRET_SALT + TEAM_ID + flag name, so flags are different per team but stay stable across
restarts of the same team. The spawner passes the salt in; the "InsecureFallbackSalt" default only
applies to a standalone docker-compose run, where flags are then guessable.
"""
import os
import hashlib
from flag_crypto import unshroud, shroud
import shutil
if not os.path.exists("flag_config_base.py"):
    shutil.copy("flag_config.py", "flag_config_base.py")
import flag_config_base as base

TEAM_ID = os.environ.get("TEAM_ID", "solo")
# Read salt from environment so participants can't see it in the source code!
SECRET_SALT = os.environ.get("FLAG_SECRET_SALT", "InsecureFallbackSalt")

PARAM_NAMES = [n for n in dir(base) if n.startswith("_PARAM_")]

lines = []
lines.append("import os")
lines.append("import hashlib")

for name in PARAM_NAMES:
    hex_blob, salt = getattr(base, name)
    plaintext = unshroud(hex_blob, salt)
    
    # Unique per team AND per flag variable name using the secret salt
    flag_hash = hashlib.md5(f"{SECRET_SALT}_{TEAM_ID}_{name}".encode()).hexdigest()[:6]
    
    if plaintext.startswith("realflag="):
        suffix = f"_{flag_hash}"
        if plaintext.endswith("}"):
            plaintext = plaintext.rstrip("}") + f"{suffix}}}"
        else:
            plaintext = plaintext + suffix
            
    new_blob = shroud(plaintext, salt)
    lines.append(f'{name} = ("{new_blob}", "{salt}")')

with open("flag_config.py", "w") as f:
    f.write("\n".join(lines) + "\n")
