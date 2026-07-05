from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import shlex
import os

app = FastAPI(title="DEU Security API")

ALLOWED_COMMANDS = {
    "nuclei": "nuclei",
    "httpx": "httpx",
    "subfinder": "subfinder",
    "katana": "katana",
    "nmap": "nmap",
    "ffuf": "ffuf",
}

class CommandRequest(BaseModel):
    tool: str
    args: str = ""

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/run")
def run_command(request: CommandRequest):
    if request.tool not in ALLOWED_COMMANDS:
        raise HTTPException(status_code=400, detail="Tool is not allowed")

    command = [ALLOWED_COMMANDS[request.tool]] + shlex.split(request.args)

    try:
        result = subprocess.run(
            command,
            cwd="/workspace",
            capture_output=True,
            text=True,
            timeout=300
        )

        return {
            "tool": request.tool,
            "command": " ".join(command),
            "exit_code": result.returncode,
            "stdout": result.stdout[-10000:],
            "stderr": result.stderr[-5000:]
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Command timeout")