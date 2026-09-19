"""
Remediator — suggested patches for confirmed findings. Model drafts the fix
(live mode); an offline fallback supplies the canonical, known-correct fix
per class. Patches are SUGGESTIONS — applying and re-scanning is on the user.
"""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

from .llm import invoke_structured
from .schemas import PatchOutput

_CANONICAL = {
    "CWE-89": {
        "before": 'query = "SELECT id, email FROM users WHERE name = \'" + name + "\'"\n'
                 'cur.execute(query)',
        "after": 'cur.execute("SELECT id, email FROM users WHERE name = ?", (name,))',
        "why": "Use a parameterized query. The database driver binds `name` as a "
              "value, so it can never be interpreted as SQL — the injection is "
              "structurally impossible, not just filtered.",
    },
    "CWE-78": {
        "before": 'subprocess.call("tar czf /tmp/" + filename + ".tgz /var/reports", '
                 'shell=True)',
        "after": 'subprocess.run(["tar", "czf", f"/tmp/{filename}.tgz", "/var/reports"], '
                "shell=False, check=True)",
        "why": "Pass arguments as a list with shell=False. Without a shell, "
              "`filename` cannot inject extra commands. Ideally also validate "
              "`filename` against an allowlist of safe characters.",
    },
    "CWE-798": {
        "before": 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        "after": 'import os\nAWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]',
        "why": "Load secrets from the environment (or a secrets manager), never "
              "from source. Then rotate the exposed key immediately, since it "
              "must be treated as compromised once it has been committed.",
    },
    "CWE-532": {
        "before": 'log.info("Login attempt user=%s password=%s", username, password)',
        "after": 'log.info("Login attempt user=%s", username)  # never log credentials',
        "why": "Remove the credential from the log statement entirely. Log the "
              "non-sensitive context you need for auditing (the username, the "
              "outcome), never the secret itself.",
    },
    "CWE-522": {
        "before": "# password compared or stored without adequate protection",
        "after": "# store only a strong salted hash (e.g. bcrypt/argon2); compare hashes",
        "why": "Never store or compare plaintext credentials; use a slow salted "
              "password hash.",
    },
}

PATCH_SYSTEM = (
    "You are a secure-coding remediation assistant. Given a vulnerability "
    "and the vulnerable code, produce a minimal corrected version."
)
PATCH_PROMPT = ChatPromptTemplate.from_messages([
    ("system", PATCH_SYSTEM), ("user", "{user_input}"),
])


def _mock_patch(finding):
    canon = _CANONICAL.get(finding.vuln_class)

    def fn():
        if canon:
            return PatchOutput(**canon)
        return PatchOutput(before="", after="", why="No canonical fix available.")
    return fn


def suggest_patches(true_positives, llm, budget, tracer=None) -> list:
    patches = []
    chain = (PATCH_PROMPT | llm) if llm is not None else None
    model_name = getattr(llm, "model", getattr(llm, "model_name", "")) if llm else ""
    for f in true_positives:
        user_input = (f"Vulnerability: {f.vuln_class} in function {f.symbol} "
                     f"(file {f.file}).\nContext: {f.investigation}\nProvide the fix.")
        out: PatchOutput = invoke_structured(
            chain, "remediator", {"user_input": user_input}, PatchOutput, model_name,
            budget, mock_fn=_mock_patch(f), tracer=tracer)
        canon = _CANONICAL.get(f.vuln_class, {})
        patches.append({
            "symbol": f.symbol, "file": f.file, "vuln_class": f.vuln_class,
            "before": out.before or canon.get("before", ""),
            "after": out.after or canon.get("after", ""),
            "why": out.why or canon.get("why", ""),
        })
    return patches
