from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
import time
import json
import statistics

# === CONNECT ===
w3 = Web3(Web3.HTTPProvider('https://purechainnode.com:8547'))
w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

contract_address = '0xC7f20054e3E29f781D5c318Db1bbaa981288dF25'
contract_abi = json.loads('''[
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

contract = w3.eth.contract(address=contract_address, abi=contract_abi)
private_key = '# ← your real key'
account = '0x30e0Fe535DEDdB072743B847eDC48bD5EC54AD02'

NUM_TRANSACTIONS = 1000

base_nonce = w3.eth.get_transaction_count(account, 'latest')
tx_hashes = []
send_times = []

# === PHASE 1: SEND ALL 1000 TXs ===
print(f"📤 Sending {NUM_TRANSACTIONS} transactions...")
overall_start = time.time()

for i in range(NUM_TRANSACTIONS):
    entity_ip = f"192.168.{i // 256}.{i % 256}"
    entity_hash_bytes32 = bytes.fromhex(Web3.keccak(
        text=entity_ip).hex()[2:]).rjust(32, b'\0')

    tx = contract.functions.logAlert(
        70000 + i, "TCP_IP-DDoS-SYN_test", 9, entity_hash_bytes32
    ).build_transaction({
        'chainId':  w3.eth.chain_id,
        'gas':      2000000,
        'gasPrice': 10,
        'nonce':    base_nonce + i,
        'from':     account,
    })

    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
    send_time = time.time()
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    send_times.append(send_time)
    tx_hashes.append(tx_hash)

    if (i + 1) % 100 == 0:
        print(f"  Sent {i + 1}/{NUM_TRANSACTIONS}...")

send_done_time = time.time()
print(
    f"✅ All {NUM_TRANSACTIONS} TXs sent in {send_done_time - overall_start:.2f}s")

# === PHASE 2: COLLECT ALL RECEIPTS ===
print(f"\n⏳ Waiting for confirmations...")
latencies = []
gas_used = []

for i, (tx_hash, send_time) in enumerate(zip(tx_hashes, send_times)):
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    confirm_time = time.time()
    latencies.append(confirm_time - send_time)
    gas_used.append(receipt['gasUsed'])

    if (i + 1) % 100 == 0:
        print(f"  Confirmed {i + 1}/{NUM_TRANSACTIONS}...")

overall_end = time.time()
total_time = overall_end - overall_start
tps = NUM_TRANSACTIONS / total_time

# === RESULTS ===
print("\n" + "=" * 55)
print("         PURECHAIN PERFORMANCE METRICS (1000 TXs)")
print("=" * 55)
print(f"  Transactions sent       : {NUM_TRANSACTIONS}")
print(f"  Total time              : {total_time:.3f} seconds")
print(f"  TPS (Throughput)        : {tps:.4f} tx/sec")
print(f"  Avg Latency             : {statistics.mean(latencies):.3f} seconds")
print(f"  Min Latency             : {min(latencies):.3f} seconds")
print(f"  Max Latency             : {max(latencies):.3f} seconds")
print(f"  Avg Gas Used per TX     : {statistics.mean(gas_used):.0f}")
print(f"  Min Gas Used            : {min(gas_used)}")
print(f"  Max Gas Used            : {max(gas_used)}")
print(f"  Total Gas Used          : {sum(gas_used)}")
print("=" * 55)
