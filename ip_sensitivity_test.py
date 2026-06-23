import time
import subprocess
import random
import numpy as np

results = {}

for ip_class, prefix in [("A", "10"), ("B", "172.16"), ("C", "192.168")]:
    latencies = []
    success = 0
    added_rules = []

    for i in range(500):
        if ip_class == "A":
            ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif ip_class == "B":
            ip = f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"

        rule_name = f"iomt_test_{ip_class}_{i}"
        added_rules.append(rule_name)

        start = time.time()
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block",
             f"remoteip={ip}", "enable=yes"],
            capture_output=True
        )
        elapsed = (time.time() - start) * 1000
        latencies.append(elapsed)

        if result.returncode == 0:
            success += 1

    # Cleanup all added rules
    for rule_name in added_rules:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={rule_name}"],
            capture_output=True
        )

    results[ip_class] = {
        "mean": round(np.mean(latencies), 2),
        "p50": round(np.percentile(latencies, 50), 2),
        "p95": round(np.percentile(latencies, 95), 2),
        "success_rate": round((success / 500) * 100, 1)
    }
    print(f"Class {ip_class}: mean={results[ip_class]['mean']}ms | "
          f"P50={results[ip_class]['p50']}ms | "
          f"P95={results[ip_class]['p95']}ms | "
          f"Success={results[ip_class]['success_rate']}%")

print("\nDone. Share these numbers to fill the table.")
