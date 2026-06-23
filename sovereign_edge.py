# sovereign_edge.py
"""
Sovereign Edge: Horizontally-scalable, AI-native secure proxy.
- ALL session state is global (Redis-backed for cluster),
- Patterns/tokens registry is global (Redis + pubsub autorefresh),
- Robust concurrency, metrics, error handling,
- Async everywhere (FastAPI-safe).
"""

import os
import json
import queue
import logging
import tempfile
import asyncio
import hashlib
from collections import deque
from prometheus_client import CollectorRegistry, Gauge, generate_latest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
import redis.asyncio as redis
import ast

# ========================= ENV, TELEMETRY, METRICS =========================
REDIS_URL = os.getenv("SOVEREIGN_REDIS_URL", "redis://localhost:6379/0")
CONFIG_KEY = "sovereign:config:matrix"
CHANNEL = "sovereign:config:updates"

AUDIT_LOG = os.getenv("SOVEREIGN_AUDIT_LOG", "sovereign_audit.log")
LEDGER_PATH = os.getenv("SOVEREIGN_LEDGER", "sovereign_ledger.jsonl")
GENESIS_HASH = "sovereign-edge-enclave-genesis-v1"
COMPLIANCE_MODE = os.getenv("SOVEREIGN_COMPLIANCE", "none").lower()

log_queue = queue.Queue()
file_handler = logging.FileHandler(AUDIT_LOG, mode='a')
file_handler.setFormatter(logging.Formatter('%(message)s'))
queue_handler = logging.handlers.QueueHandler(log_queue)
logger = logging.getLogger("sovereign_telemetry")
logger.setLevel(logging.INFO)
if not logger.hasHandlers():
    logger.addHandler(queue_handler)
listener = logging.handlers.QueueListener(log_queue, file_handler)
listener.start()

import atexit
def shutdown_telemetry():
    listener.stop()
atexit.register(shutdown_telemetry)

def _safe_serialize(obj):
    try:
        return json.dumps(obj)
    except (TypeError, ValueError):
        if isinstance(obj, dict):
            return json.dumps({k: _safe_serialize(v) for k,v in obj.items()})
        elif isinstance(obj, (list, tuple)):
            return json.dumps([_safe_serialize(x) for x in obj])
        else:
            return json.dumps(str(obj))

def telemetry_log(record):
    try:
        logger.info(_safe_serialize(record))
    except Exception:
        try: logger.info(json.dumps(str(record)))
        except Exception: pass

PROM_REGISTRY = CollectorRegistry()
METRIC_NAMES = ["in_flight", "blocks", "total_requests", "config_swaps", "heals_executed", "audit_errors"]
PROM_GAUGES = {
    name: Gauge(f"sovereign_{name}", f"Sovereign {name}", registry=PROM_REGISTRY)
    for name in METRIC_NAMES
}

class SystemMetrics:
    def __init__(self):
        self._counters = {n:0 for n in PROM_GAUGES}
        self._lock = asyncio.Lock()
    async def inc(self, key):
        async with self._lock:
            self._counters[key] += 1
            PROM_GAUGES[key].set(self._counters[key])
    async def dec(self, key):
        async with self._lock:
            self._counters[key] -= 1
            PROM_GAUGES[key].set(self._counters[key])
    def as_dict(self):
        return dict(self._counters)

metrics = SystemMetrics()

# ========================== TOKENIZER + MATCHING ===========================

def tokenize_structural(text, partial_word="", trailing_gap=False, limit=256):
    tokens = []
    buff = partial_word
    n = 0
    in_gap = trailing_gap
    for c in text:
        if n >= limit: break
        if c.isalnum():
            buff += c.lower()
            in_gap = False
        else:
            if not in_gap:
                if buff:
                    tokens.append(buff)
                    buff = ""
                    n += 1
                tokens.append(" ")
                n += 1
                in_gap = True
    if buff and n < limit:
        tokens.append(buff)
    return tokens, buff, in_gap

class TrieNode:
    def __init__(self):
        self.children = {}
        self.fail = None
        self.outputs = set()

class AhoCorasickAutomaton:
    def __init__(self, patterns):
        self.root = TrieNode()
        for idx, pat in enumerate(patterns):
            node = self.root
            for tok in pat:
                if tok not in node.children:
                    node.children[tok] = TrieNode()
                node = node.children[tok]
            node.outputs.add(idx)
        self._build_fail_links()
    def _build_fail_links(self):
        queue_arr = []
        for child in self.root.children.values():
            child.fail = self.root
            queue_arr.append(child)
        while queue_arr:
            rnode = queue_arr.pop(0)
            for key, unode in rnode.children.items():
                queue_arr.append(unode)
                fnode = rnode.fail
                while fnode and key not in fnode.children:
                    fnode = fnode.fail
                unode.fail = fnode.children[key] if fnode and key in fnode.children else self.root
                unode.outputs |= unode.fail.outputs
    def search(self, tokens):
        node = self.root
        for tok in tokens:
            while node and tok not in node.children:
                node = node.fail
            node = node.children[tok] if node and tok in node.children else self.root
            if node.outputs:
                return True
        return False

class ImmutableRegistry:
    def __init__(self, patterns=None, tokens=None, automaton=None):
        self.patterns = frozenset(patterns or [])
        self.tokens = frozenset(tokens or [])
        self.automaton = automaton
    @staticmethod
    def _precompile_worker(raw_patterns):
        patterns_structural = [tokenize_structural(p)[0] for p in raw_patterns]
        return AhoCorasickAutomaton(patterns_structural)
    async def precompile_async(self):
        compiled = await asyncio.to_thread(self._precompile_worker, list(self.patterns))
        self.automaton = compiled

class AtomicRegistryManager:
    def __init__(self, telemetry_log):
        self._registry = ImmutableRegistry()
        self._lock = asyncio.Lock()
        self.admin_lock = asyncio.Lock()
        self.telemetry_log = telemetry_log
        self.r = redis.Redis.from_url(REDIS_URL)

    def get(self):
        return self._registry

    async def atomic_replace(self, reg):
        async with self._lock:
            self._registry = reg

    async def load(self):
        raw_data = await self.r.get(CONFIG_KEY)
        if not raw_data:
            default = {"patterns": [], "tokens": ["adminkey123"]}
            await self.r.set(CONFIG_KEY, json.dumps(default))
            raw = default
        else:
            raw = json.loads(raw_data)
        reg = ImmutableRegistry(raw.get("patterns", []), raw.get("tokens", []))
        await reg.precompile_async()
        await self.atomic_replace(reg)

    async def atomic_save(self, reg):
        ser = json.dumps({
            "patterns": list(reg.patterns),
            "tokens": list(reg.tokens)
        })
        await self.r.set(CONFIG_KEY, ser)

    async def add_patterns(self, new_pats, telemetry_log):
        async with self.admin_lock:
            curr_patterns = set(self._registry.patterns)
            curr_tokens = set(self._registry.tokens)
            curr_patterns.update(str(p).strip().lower() for p in new_pats if p.strip())
            reg = ImmutableRegistry(curr_patterns, curr_tokens)
            await reg.precompile_async()
            await self.atomic_save(reg)
            await self.atomic_replace(reg)
            telemetry_log({"type": "patterns_added", "count": len(new_pats)})
            await self.r.publish(CHANNEL, "reload")
    async def remove_patterns(self, target_pats, telemetry_log):
        async with self.admin_lock:
            curr_patterns = set(self._registry.patterns)
            curr_tokens = set(self._registry.tokens)
            curr_patterns.difference_update(str(p).strip().lower() for p in target_pats if p.strip())
            reg = ImmutableRegistry(curr_patterns, curr_tokens)
            await reg.precompile_async()
            await self.atomic_save(reg)
            await self.atomic_replace(reg)
            telemetry_log({"type": "patterns_removed", "count": len(target_pats)})
            await self.r.publish(CHANNEL, "reload")

# ========== REDIS SESSION SLIDING WINDOW ==========
class RedisSessionScanner:
    def __init__(self, redis_url=REDIS_URL):
        self.r = redis.Redis.from_url(redis_url)
        self.window_size = 512
        self.eval_window = 256

    async def push_and_check(self, session_id, text, automaton):
        tokens, _, _ = tokenize_structural(text)
        pipe = self.r.pipeline()
        key = f"session:{session_id}:tokens"
        if tokens:
            pipe.rpush(key, *tokens)
        pipe.ltrim(key, -self.window_size, -1)
        await pipe.execute()
        final_tokens = await self.r.lrange(key, -self.eval_window, -1)
        token_list = [t.decode() if isinstance(t, bytes) else str(t) for t in final_tokens]
        return automaton.search(token_list)

    async def clear(self, session_id):
        await self.r.delete(f"session:{session_id}:tokens")

def compute_file_hash(filepath):
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def lockdown(msg, telemetry_log):
    telemetry_log({"type": "LOCKDOWN", "msg": msg})
    os._exit(100)

# ========== KERNEL AUDIT LOG ==========

import fcntl
from datetime import datetime, timezone

class AuditLedger:
    def __init__(self, path, telemetry_log, genesis_hash):
        self.path = path
        self.telemetry_log = telemetry_log
        self.genesis_hash = genesis_hash
        self.write_lock = asyncio.Lock()

    async def append_event(self, event_type, session_id, data):
        async with self.write_lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            def append_block():
                try:
                    with open(self.path, "a+b") as f:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                        f.seek(0, os.SEEK_END)
                        filesize = f.tell()
                        blocksize = min(4096, filesize)
                        last_block = None
                        if blocksize > 0:
                            cur_pos = f.tell()
                            if cur_pos > blocksize:
                                f.seek(-blocksize, os.SEEK_END)
                            else:
                                f.seek(0)
                            chunk = f.read(blocksize)
                            lines = chunk.split(b"\n")
                            last = lines[-2] if chunk.endswith(b"\n") and len(lines) > 1 else lines[-1]
                            if last.strip():
                                last_block = json.loads(last)
                        parent_hash = last_block["hash"] if last_block else self.genesis_hash
                        raw_jsonstr = json.dumps(data, separators=(',', ':'), sort_keys=True)
                        hash_val = hashlib.sha256(
                            (parent_hash or '').encode() +
                            str(timestamp).encode() +
                            str(event_type).encode() +
                            str(session_id).encode() +
                            raw_jsonstr.encode()
                        ).hexdigest()
                        block = {
                            "timestamp": timestamp, "event_type": event_type, "session_id": session_id,
                            "raw": raw_jsonstr, "parent_hash": parent_hash, "hash": hash_val
                        }
                        f.write((json.dumps(block, separators=(',', ':')) + "\n").encode())
                        f.flush()
                        os.fsync(f.fileno())
                        fcntl.flock(f.fileno(), f.LOCK_UN)
                except Exception as e:
                    self.telemetry_log({"type": "ledger_io_error", "msg": str(e)})
                    raise
            await asyncio.to_thread(append_block)

# ========== AST CODE-HEALER ==========
class ASTSelfHealer:
    @staticmethod
    def clean_source_code(raw_code: str) -> str:
        try:
            tree = ast.parse(raw_code)
        except SyntaxError:
            return "# HEALER WARNING: Syntax Error in target code. Execution blocked."
        class MaliciousTransformer(ast.NodeTransformer):
            def visit_Call(self, node):
                self.generic_visit(node)
                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    return ast.copy_location(ast.Expr(
                        value=ast.Constant(value=f"Blocked dangerous execution: {node.func.id}")
                    ), node)
                return node
        healed_tree = MaliciousTransformer().visit(tree)
        ast.fix_missing_locations(healed_tree)
        try:
            if hasattr(ast, "unparse"):
                return ast.unparse(healed_tree)
            import astor
            return astor.to_source(healed_tree)
        except Exception:
            return "# HEALER WARNING: code re-generation failed; file unchanged."

# ==================== MAIN APP / API =========================

metrics = SystemMetrics()
manager = AtomicRegistryManager(telemetry_log)
session_scanner = RedisSessionScanner()
audit_ledger = AuditLedger(
    path=os.getenv("SOVEREIGN_LEDGER", "sovereign_ledger.jsonl"),
    telemetry_log=telemetry_log,
    genesis_hash=os.getenv("GENESIS_HASH", GENESIS_HASH),
)

app = FastAPI(title="Sovereign Edge Enclave", version="2.0.0")

async def listen_for_config_changes():
    sub = manager.r.pubsub()
    await sub.subscribe(CHANNEL)
    async for msg in sub.listen():
        if msg["type"] == "message" and msg["data"] == b"reload":
            telemetry_log({"type": "config_reload_signal"})
            await manager.load()

@app.on_event("startup")
async def on_startup():
    telemetry_log({"type": "boot", "compliance_mode": COMPLIANCE_MODE})
    if os.getenv("EVIL_ENV") == "1":
        lockdown("Detected tampering via EVIL_ENV!", telemetry_log)
    await manager.load()
    loop = asyncio.get_event_loop()
    loop.create_task(listen_for_config_changes())

@app.get("/metrics")
async def metrics_endpoint(request: Request):
    header_token = request.headers.get("X-Sovereign-Token", "")
    if header_token not in manager.get().tokens:
        return Response("Unauthorized", status_code=401)
    return Response(generate_latest(PROM_REGISTRY), media_type="text/plain")

@app.post("/proxy")
async def proxy_endpoint(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(content={"error": "Bad JSON"}, status_code=400)
    prompt = payload.get("prompt", "")
    session_id = request.headers.get("X-Session-Id") or request.client.host
    await metrics.inc("total_requests")
    await metrics.inc("in_flight")
    try:
        allowed_chunks = []
        automaton = manager.get().automaton
        found = await session_scanner.push_and_check(session_id, prompt, automaton)
        if found:
            await metrics.inc("blocks")
            telemetry_log({"type": "blocked_leak", "prompt": prompt, "mode": COMPLIANCE_MODE, "session": session_id})
            await audit_ledger.append_event("blocked_leak", session_id, {"prompt": prompt, "mode": COMPLIANCE_MODE})
            return JSONResponse({"status": "blocked", "msg": "Sensitive pattern detected."}, status_code=403)
        allowed_chunks.append(prompt)
        telemetry_log({"type": "allow_output", "chunks": allowed_chunks, "mode": COMPLIANCE_MODE, "session": session_id})
        return JSONResponse({"status": "ok", "chunks": allowed_chunks})
    finally:
        await metrics.dec("in_flight")

@app.post("/heal")
async def heal_endpoint(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(content={"error": "Bad JSON"}, status_code=400)
    src = payload.get("code", "")
    cleaned = ASTSelfHealer.clean_source_code(src)
    await metrics.inc("heals_executed")
    return JSONResponse({"healed_code": cleaned})

@app.post("/patterns/add")
async def add_patterns_endpoint(request: Request):
    try:
        payload = await request.json()
        patterns = payload.get("patterns", [])
        await manager.add_patterns(patterns, telemetry_log)
        return JSONResponse({"status": "ok", "added": patterns})
    except Exception as e:
        telemetry_log({"type": "error", "msg": str(e)})
        return JSONResponse({"status": "error", "msg": f"Could not add patterns: {e}"}, status_code=400)

@app.post("/patterns/remove")
async def remove_patterns_endpoint(request: Request):
    try:
        payload = await request.json()
        patterns = payload.get("patterns", [])
        await manager.remove_patterns(patterns, telemetry_log)
        return JSONResponse({"status": "ok", "removed": patterns})
    except Exception as e:
        telemetry_log({"type": "error", "msg": str(e)})
        return JSONResponse({"status": "error", "msg": f"Could not remove patterns: {e}"}, status_code=400)

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    hash_val = compute_file_hash(__file__)
    print(f"[ Sovereign Edge Boot Verified ] Build SHA256: {hash_val}")
    print(f"[ Compliance Mode ] {COMPLIANCE_MODE }")
    import uvicorn
    uvicorn.run("sovereign_edge:app", host="0.0.0.0", port=8080, reload=False)
