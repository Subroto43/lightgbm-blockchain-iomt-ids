# stress_test.py — Section V Performance Test for IEEE Paper

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
import time
import json
import statistics
import subprocess
import threading

RPC_URL = "https://purechainnode.com:8547"
CONTRACT = "0xC7f20054e3E29f781D5c318Db1bbaa981288dF25"
PRIVATE_KEY = "# ← your real key"
ACCOUNT = "0x30e0Fe535DEDdB072743B847eDC48bD5EC54AD02"
THRESHOLD = 7

ABI = json.loads('[{"inputs":[{"internalType":"uint256","name":"threatId","type":"uint256"},{"internalType":"string","name":"threatType","type":"string"},{"internalType":"uint256","name":"severity","type":"uint256"},{"internalType":"bytes32","name":"entityHash","type":"bytes32"}],"name":"logAlert","outputs":[],"stateMutability":"nonpayable","type":"function"}]')

w3 = Web3(Web3.HTTPProvider(RPC_URL))
w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
contract = w3.eth.contract(address=CONTRACT, abi=ABI)
print(f"Connected: {w3.is_connected()} | Chain ID: {w3.eth.chain_id}")

nonce_lock = threading.Lock()
nonce_counter = [None]  # initialized before each phase


def reset_nonce():
    """Call this before each phase to resync nonce from chain."""
    with nonce_lock:
        nonce_counter[0] = w3.eth.get_transaction_count(ACCOUNT, 'pending')
    print(f"  [nonce reset to {nonce_counter[0]}]")


def send_alert(threat_id, threat_type="TCPIP-DDoS-SYNtest", severity=9, ip="10.0.0.1"):
    entity_hash = Web3.keccak(text=ip)
    entity_bytes32 = bytes.fromhex(entity_hash.hex()[2:]).rjust(32, b'\x00')

    # ── get unique nonce from counter (thread-safe increment)
    with nonce_lock:
        n = nonce_counter[0]
        nonce_counter[0] += 1

    t_detect = time.perf_counter()

    tx = contract.functions.logAlert(
        threat_id, threat_type, severity, entity_bytes32
    ).build_transaction({
        'chainId': w3.eth.chain_id,
        'gas': 200000,
        'gasPrice': 10,
        'nonce': n,
        'from': ACCOUNT,
    })
    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)

    t_commit_start = time.perf_counter()
    try:
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        success = receipt.status == 1
    except Exception as e:
        print(f"    ⚠ nonce={n} error: {str(e)[:60]}")
        success = False

    t_commit_end = time.perf_counter()

    t_rule_start = time.perf_counter()
    if severity >= THRESHOLD and success:
        rule_name = f"Block_{entity_hash.hex()[:16]}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block",
             "remoteip=any", "enable=yes"],
            capture_output=True, text=True
        )
    t_rule_end = time.perf_counter()

    return {
        "detect_ms": (t_commit_start - t_detect) * 1000,
        "commit_ms": (t_commit_end - t_commit_start) * 1000,
        "rule_ms":   (t_rule_end - t_rule_start) * 1000,
        "e2e_ms":    (t_rule_end - t_detect) * 1000,
        "success":   success
    }


def percentile(data, p):
    return sorted(data)[int(len(data) * p / 100)]


# ─── PHASE A — sequential ───
print("\n=== PHASE A: Baseline P50/P95 (50 alerts, sequential) ===")
reset_nonce()
results_A = []
for i in range(50):
    r = send_alert(threat_id=90000 + i, ip=f"10.1.0.{i % 255 + 1}")
    results_A.append(r)
    print(f"  [{i+1}/50] detect={r['detect_ms']:.1f}ms  commit={r['commit_ms']:.0f}ms  rule={r['rule_ms']:.0f}ms  e2e={r['e2e_ms']:.0f}ms  ok={r['success']}")

for key, label in [("detect_ms", "Detection"), ("commit_ms", "Chain Commit"), ("rule_ms", "Rule Application"), ("e2e_ms", "End-to-End")]:
    vals = [r[key] for r in results_A]
    print(f"  {label}: P50={percentile(vals, 50):.1f}ms  P95={percentile(vals, 95):.1f}ms  mean={statistics.mean(vals):.1f}ms")

# ─── PHASE B — concurrent ───
print("\n=== PHASE B: Concurrent scaling ===")
for concurrency in [10, 50, 100]:
    reset_nonce()  # ← fresh nonce before each batch
    bucket = []
    threads = []

    def worker(tid):
        r = send_alert(threat_id=80000 + tid,
                       ip=f"10.2.{tid//255}.{tid % 255+1}")
        bucket.append(r)

    t_start = time.perf_counter()
    for j in range(concurrency):
        t = threading.Thread(target=worker, args=(j,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t_start

    e2e_vals = [r["e2e_ms"] for r in bucket]
    actual_tps = concurrency / elapsed
    success_rate = sum(r["success"] for r in bucket) / len(bucket) * 100
    print(f"  {concurrency} concurrent | TPS={actual_tps:.1f} | success={success_rate:.0f}% | P50={percentile(e2e_vals, 50):.0f}ms | P95={percentile(e2e_vals, 95):.0f}ms")

# ─── PHASE C — TPS stress ───
print("\n=== PHASE C: TPS Stress Test ===")
for target_tps in [66, 100, 150, 200]:
    reset_nonce()  # ← fresh nonce before each batch
    batch_size = target_tps
    bucket = []
    threads = []

    t_start = time.perf_counter()
    for k in range(batch_size):
        t = threading.Thread(target=lambda k=k: bucket.append(
            send_alert(threat_id=70000 + k + target_tps * 10,
                       ip=f"10.3.{k//255}.{k % 255+1}")
        ))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t_start

    actual_tps = batch_size / elapsed
    success_rate = sum(r["success"] for r in bucket) / len(bucket) * 100
    e2e_vals = [r["e2e_ms"] for r in bucket]
    print(f"  Target={target_tps} TPS | Actual={actual_tps:.1f} TPS | success={success_rate:.0f}% | P95 e2e={percentile(e2e_vals, 95):.0f}ms")

# ─── SUMMARY TABLE ───
print("\n" + "="*60)
print("SECTION V TABLE — Latency Percentiles (copy to paper)")
print("="*60)
for key, label in [("detect_ms", "Detection"), ("commit_ms", "Chain Commit"), ("rule_ms", "Rule Application"), ("e2e_ms", "End-to-End")]:
    vals = [r[key] for r in results_A]
    print(f"| {label:<20} | P50={percentile(vals, 50):7.1f} ms | P95={percentile(vals, 95):7.1f} ms |")
