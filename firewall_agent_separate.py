from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
import subprocess
import time
import json

# === CONFIGURATION ===
rpc_url = "https://purechainnode.com:8547"
contract_address = "0xC7f20054e3E29f781D5c318Db1bbaa981288dF25"
SEVERITY_THRESHOLD = 7
POLL_INTERVAL = 5

contract_abi = json.loads('''[
    {
        "anonymous": false,
        "inputs": [
            {"indexed": false, "internalType": "uint256", "name": "threatId",   "type": "uint256"},
            {"indexed": false, "internalType": "string",  "name": "threatType", "type": "string"},
            {"indexed": false, "internalType": "uint256", "name": "severity",   "type": "uint256"}
        ],
        "name": "AlertLogged",
        "type": "event"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "threatId",   "type": "uint256"},
            {"internalType": "string",  "name": "threatType", "type": "string"},
            {"internalType": "uint256", "name": "severity",   "type": "uint256"},
            {"internalType": "bytes32", "name": "entityHash", "type": "bytes32"}
        ],
        "name": "logAlert",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]''')

# === CONNECT TO PURECHAIN ===
w3 = Web3(Web3.HTTPProvider(rpc_url))
w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

if not w3.is_connected():
    print("❌ Cannot connect to PureChain node. Exiting.")
    exit()

print(f"✅ Connected to PureChain | Chain ID: {w3.eth.chain_id}")

contract = w3.eth.contract(address=contract_address, abi=contract_abi)
blocked_cache = set()

# === FIREWALL BLOCK FUNCTION ===


def block_ip_in_firewall(entity_hash_hex):
    rule_name = f"Block_{entity_hash_hex[:16]}"

    result = subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        "remoteip=any",
        "enable=yes"
    ], capture_output=True, text=True)

    if result.returncode == 0:
        print(f"   🔥 Firewall rule added: {rule_name}")
    else:
        print(f"   ⚠️  Firewall rule failed: {result.stderr.strip()}")


# === MAIN AGENT LOOP ===
print(
    f"🔍 Firewall agent started | Severity threshold: {SEVERITY_THRESHOLD} | Polling every {POLL_INTERVAL}s")
print("─" * 60)

last_block = w3.eth.block_number

while True:
    try:
        current_block = w3.eth.block_number

        if current_block > last_block:
            events = contract.events.AlertLogged.get_logs(
                from_block=last_block + 1,
                to_block=current_block
            )

            for event in events:
                threat_id = event['args']['threatId']
                threat_type = event['args']['threatType']
                severity = event['args']['severity']

                print(
                    f"\n[NEW] ThreatID: {threat_id} | Type: {threat_type} | Severity: {severity}")

                if severity >= SEVERITY_THRESHOLD:
                    print(
                        f"   ⚠️  Severity {severity} >= {SEVERITY_THRESHOLD} — blocking entity...")

                    # ← decode entityHash directly from transaction input
                    try:
                        tx_data = w3.eth.get_transaction(
                            event['transactionHash'])
                        decoded = contract.decode_function_input(
                            tx_data['input'])
                        entity_hash_hex = decoded[1]['entityHash'].hex()

                        if entity_hash_hex not in blocked_cache:
                            blocked_cache.add(entity_hash_hex)
                            print(
                                f"   🚨 BLOCKING entity hash: {entity_hash_hex}")
                            print(
                                f"   📦 Total blocked so far: {len(blocked_cache)}")
                            block_ip_in_firewall(entity_hash_hex)
                        else:
                            print(f"   ℹ️  Already blocked: {entity_hash_hex}")

                    except Exception as decode_err:
                        print(
                            f"   ⚠️  Could not decode entity hash: {decode_err}")

                else:
                    print(
                        f"   ✅ Severity {severity} < {SEVERITY_THRESHOLD} — no action taken.")

            last_block = current_block

        time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user.")
        print(f"📊 Total entities blocked this session: {len(blocked_cache)}")
        break
    except Exception as e:
        print(f"[!] Error: {e}")
        time.sleep(POLL_INTERVAL)
