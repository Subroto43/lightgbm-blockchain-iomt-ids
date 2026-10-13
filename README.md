# Decentralized Intrusion Detection and Prevention Leveraging Lightweight ML for Securing IoMT Networks

Official source code for the paper:

> **Decentralized Intrusion Detection and Prevention Leveraging Lightweight ML Model for Securing IoMT Networks**
> S. K. Ghosh, M. Golam, S. Bin Noor, J.-M. Lee, and D.-S. Kim
> *IEEE Internet of Things Journal*, 2026. DOI: `10.1109/JIOT.2026.3707196`

This repository provides the complete, reproducible implementation of a **closed-loop, blockchain-empowered intrusion detection and prevention framework** for the Internet of Medical Things (IoMT). The framework couples a lightweight **LightGBM** classifier with a **permissioned blockchain (Pure Chain)** and an **automated firewall enforcement** module, delivering a verifiable detection-to-response pipeline.

---

## Framework overview

The pipeline integrates four functional layers and runs as an end-to-end loop from detection to mitigation:

```
   IoMT traffic (CIC-IoMT 2024)
            │
            ▼
 ┌─────────────────────────┐   1. Detection
 │  LightGBM IDS            │   multi-class flow classification (21 classes)
 │  (lightweight, 3.22 MB)  │   → threat type + severity score + source IP
 └─────────────────────────┘
            │ keccak256(source IP) = entityHash   (plus a local hash→IP map)
            │ logAlert(threatId, threatType, severity, entityHash)
            ▼
 ┌─────────────────────────┐   2. Immutable logging
 │  Pure Chain smart        │   only the keccak256 hash is written on-chain
 │  contract (PoA²)         │   severity ≥ 7  →  entity marked blocked
 └─────────────────────────┘   emits AlertLogged / ResponseTriggered / Blocked
            │ polls AlertLogged events every 5 s
            ▼
 ┌─────────────────────────┐   3. Enforcement
 │  Python firewall agent   │   decodes entityHash → resolves the real IP via
 │  (netsh advfirewall)     │   the local hash→IP map → installs an OS-level
 └─────────────────────────┘   block rule (remoteip=<ip>) for severity ≥ 7
```

**Privacy / enforcement note.** keccak256 is a one-way hash and is *not* reversed. Only the hash is stored on-chain, for privacy. The gateway keeps a small **local, off-chain map** (`hash_to_ip.json`) that pairs each hash with the original source IP at the moment the alert is generated. The firewall agent resolves the hash to the real IP through this map (a lookup, not a cryptographic inversion) and blocks that specific address. In this single-gateway prototype the detector, the map, and the agent run on the same host, which already holds the plaintext IP.

---

## Repository structure

| File | Role | Paper section |
|------|------|---------------|
| `dataset_add.py` | Adds per-class **severity scores** and **synthetic RFC-1918 source/destination IPs** to the dataset (IPs are used only for firewall routing, **never** as model features). | §IV-B, Table III |
| `Hybrid_model_updated.ipynb` | Main notebook: preprocessing, **LightGBM** (proposed IDS), **LSTM** and **Hybrid (LGBM+LSTM)** baselines, evaluation, figures, and on-chain alert logging via Web3. Writes the local `hash_to_ip.json` map when sending alerts. | §IV-C/D, §V-A/D/E, Tables V–VI |
| `xgboost_svm_rf.py` | **XGBoost**, **Random Forest**, and **SVM (RBF)** comparison baselines under the identical pipeline. | §IV-D, Table VI |
| `smart_contract.sol` | `IntrusionBlockerWithResponse` — Solidity contract for severity-aware alert logging and on-chain blocking. | §III-G, Algorithm 1 |
| `firewall_agent_separate.py` | Standalone agent that polls the contract, resolves each hash to the real IP via `hash_to_ip.json`, and enforces Windows firewall rules. **Run as Administrator.** | §III-H, Algorithm 2 |
| `purechain_metrics.py` | Blockchain benchmark: gas cost, transaction latency, throughput (TPS). | §V-I, Table VII |
| `stress_test.py` | Sequential + concurrent load/stress test of the detection-to-response pipeline. **Run as Administrator.** | §V-K/L, Tables VIII–X |
| `ip_sensitivity_test.py` | IP-class (A/B/C) firewall rule-application sensitivity study. **Run as Administrator.** | §IV-B, Table IV |
| `hash_to_ip.json` | **Generated at runtime** (not committed): local off-chain map from entity hash to the real source IP, used only for enforcement. Add it to `.gitignore`. | §III-H |

---

## Dataset

The framework is evaluated on the **CIC-IoMT 2024** benchmark (WiFi + MQTT traffic), a public dataset from the Canadian Institute for Cybersecurity (UNB).

- Source: Canadian Institute for Cybersecurity — *CICIoMT2024* (https://www.unb.ca/cic/datasets/).
- Reference: S. Dadkhah et al., *"CICIoMT2024: A benchmark dataset for multi-protocol security assessment in IoMT," Internet of Things*, vol. 28, 101351, 2024.
- File used: `CIC_IoMT_2024_WiFi_MQTT_test.csv` (treated as the full labeled set, then re-split with a fixed-seed stratified 70/15/15 partition). After cleaning, **45 numerical features** and **1,614,182 samples** across **21 classes** are retained. The 21 labels arise from the WiFi/MQTT attack types at their finer recorded granularity (e.g. DDoS ICMP/UDP each appear as two numbered variants) plus benign traffic.

**Note on IP addresses.** The original CIC-IoMT 2024 capture anonymizes IP headers, so `dataset_add.py` generates **synthetic** Class A/B/C private IPs purely as routing identifiers for the firewall demonstration. These synthetic IPs and the derived `Severity_Score` are **excluded from the ML feature set** to prevent any training bias / leakage.

Download the dataset and update the file path at the top of each script/notebook before running.

---

## Requirements

- **Python 3.10+**
- **Windows 10/11** for the firewall-enforcement and stress-test scripts (they use `netsh advfirewall`). The detection/training code itself is OS-independent. *On Linux, the equivalent `iptables`/`ufw` rules apply.*
- Access to a **Pure Chain** (Ethereum-compatible PoA²) RPC endpoint for the blockchain components.

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

`requirements.txt`:
```
pandas
numpy
scikit-learn
lightgbm
xgboost
tensorflow
scipy
matplotlib
seaborn
web3>=7.0
```

---

## Setup: blockchain credentials (no key is included)

For security, **no private key is shipped in this repository.** The blockchain scripts read the key from an environment variable; nothing is hard-coded. Supply your own key before running any on-chain component.

**Recommended — environment variable** (do not hardcode):

```powershell
# PowerShell
$env:PURECHAIN_PRIVATE_KEY = "your_private_key_here"
```
```python
import os
private_key = os.environ["PURECHAIN_PRIVATE_KEY"]
```

Set the following near the top of `purechain_metrics.py`, `stress_test.py`, and the relevant notebook cells:

| Variable | Description |
|----------|-------------|
| `PURECHAIN_PRIVATE_KEY` (env) | Your funded Pure Chain account key (keep secret; never commit). |
| `account` | The public address derived from your key. |
| `contract_address` | Address of your deployed `IntrusionBlockerWithResponse` contract. |
| `rpc_url` | Your Pure Chain RPC endpoint. |

> Only the components that **send** transactions (the notebook's alert-logging cells, `purechain_metrics.py`, `stress_test.py`) need the private key. `firewall_agent_separate.py` only **reads** events and applies firewall rules, so it does not need the key.

---

## Usage

Run in the following order to reproduce the full pipeline.

### 1. Prepare the dataset
```bash
python dataset_add.py
```
Produces the dataset with `Severity_Score`, `Source_IP`, and `Destination_IP` columns.

### 2. Train and evaluate the models
Open and run the notebook for the proposed LightGBM IDS and the LSTM / Hybrid models:
```bash
jupyter notebook Hybrid_model_updated.ipynb
```
Run the gradient-boosting / classical baselines:
```bash
python xgboost_svm_rf.py
```
These produce the accuracy/F1, latency, model-size, and per-class metrics, plus the confusion matrices and feature-importance plots.

### 3. Deploy the smart contract
Deploy `smart_contract.sol` (Solidity `^0.8.0`) to your Pure Chain network — e.g. via Remix or your preferred toolchain — passing the constructor argument:
```
_severityThreshold = 7
```
Record the deployed contract address and set it in the scripts.

### 4. Log alerts on-chain
Run the blockchain-logging cells in `Hybrid_model_updated.ipynb` to submit detected alerts to the contract via `logAlert(...)`. These cells also write `hash_to_ip.json`, the local map the firewall agent uses to resolve each hash to its real IP.

### 5. Start the firewall enforcement agent — **as Administrator**
`firewall_agent_separate.py` adds OS-level firewall rules with `netsh advfirewall`, which **requires elevated privileges**. It reads `hash_to_ip.json` and blocks the resolved source IP (`remoteip=<ip>`) for any entity with severity ≥ 7.

> **Open PowerShell as Administrator** (right-click PowerShell → *Run as administrator*), then:
```powershell
python firewall_agent_separate.py
```
The agent polls `AlertLogged` events every 5 seconds. Without administrator rights, `netsh` will fail to add rules.

### 6. (Optional) Reproduce the benchmarks
```powershell
python purechain_metrics.py        # gas, latency, TPS (Table VII)
python stress_test.py              # sequential + concurrent load (Tables VIII–X) — Administrator
python ip_sensitivity_test.py      # IP-class firewall latency (Table IV) — Administrator
```
`stress_test.py` and `ip_sensitivity_test.py` also issue `netsh` commands and must be run in an **Administrator** PowerShell.

---

## Smart contract

**`IntrusionBlockerWithResponse`** (Solidity `^0.8.0`), deployed on a permissioned, Ethereum-compatible Pure Chain network under PoA² consensus.

**Key functions**
- `logAlert(uint threatId, string threatType, uint severity, bytes32 entityHash)` — logs an alert; auto-blocks the entity if `severity ≥ severityThreshold`. *(owner only)*
- `isBlocked(bytes32 entityHash) → bool` — query blocked state.
- `unblockEntity(bytes32 entityHash)` — unblock an entity. *(owner only)*
- `updateSeverityThreshold(uint newThreshold)` — update the threshold. *(owner only)*

**Events:** `AlertLogged`, `ResponseTriggered`, `Blocked`, `Unblocked`.

Source IPs are hashed with **keccak256** before submission, so raw identifiers are never written on-chain; the original address is resolved locally through the off-chain `hash_to_ip.json` map for enforcement only. The contract was scanned with **SolidityScan** (automated vulnerability scan: **97/100, Low Risk**). This is a static scan rather than a formal audit.

---

## Results (summary)

Model comparison on CIC-IoMT 2024 (mean over 5 seeds; see paper Table VI):

| Model | Accuracy | F1 | Inference (ms/sample) | Size (MB) |
|-------|---------:|---:|----------------------:|----------:|
| **LightGBM (proposed)** | **97.9%** | **97.9%** | **0.003** | **3.22** |
| XGBoost | 98.0% | 98.0% | 0.007 | 12.27 |
| Random Forest | 98.1% | 98.1% | 0.009 | 1,350 |
| LSTM | 91.8% | 91.8% | 0.169 | 15.09 |
| Hybrid (LGBM+LSTM) | 97.9% | 97.9% | 0.191 | 18.31 |
| SVM (RBF) | 64.0% | 57.0% | 52.256 | 361.8 |

Blockchain (Pure Chain): ~45 ms average `logAlert` latency, 66.85 TPS raw throughput, gas 23,314–27,627 units.

**Latency note.** The single-alert detection-to-enforcement **processing** cost is ≈ 73 ms (inference 0.003 ms + chain confirmation 45 ms + firewall rule 28 ms). This **excludes** the 5-second agent polling interval, so the live wall-clock response is bounded by that interval, not by 73 ms. Under concurrent bursts the median end-to-end latency rises from ≈ 2.07 s at 10 simultaneous alerts to ≈ 6.11 s at 100, with a 100% logging success rate throughout (paper Tables VIII–X).

---

## Security and responsible use

- **No private keys are included** in this repository, and the scripts read the key from the `PURECHAIN_PRIVATE_KEY` environment variable. Keep credentials out of version control (use environment variables / a git-ignored `.env`).
- **Do not commit `hash_to_ip.json`** — it maps hashes to real IPs. Add it to `.gitignore`.
- The account and contract addresses in the code refer to a **private, permissioned** test network and are safe to publish, but you should deploy and point to **your own** contract for any real use.
- The synthetic IP addresses exist only to demonstrate firewall enforcement; deploy with authentic packet sources for production.

---

## Citation

If you use this code, please cite:

```bibtex
@ARTICLE{11579356,
  author={Ghosh, Subroto Kumar and Golam, Mohtasin and Noor, Sium Bin and Lee, Jae Min and Kim, Dong-Seong},
  journal={IEEE Internet of Things Journal},
  title={Decentralized Intrusion Detection and Prevention Leveraging Lightweight ML Model for Securing IoMT Networks},
  year={2026},
  volume={},
  number={},
  pages={1-1},
  keywords={Modeling;Internet of Things;Intrusion detection;Timing;IP networks;Signal detection;Firewalls (computing);Training;Accuracy;TCP;Intrusion Detection;IoMT;LightGBM;Blockchain-Empowered;Real-Time Threat Mitigation;Smart Contract Enforcement},
  doi={10.1109/JIOT.2026.3707196}}

```

---

## License

Released under the **MIT License** (consistent with the smart contract's SPDX identifier). Add a `LICENSE` file to the repository, or change this if you prefer a different license.

---

## Acknowledgment

This work was partly supported by Innovative Human Resource Development for Local Intellectualization program through the IITP grant funded by the Korea government (MSIT) (IITP-2026-RS-2020-II201612, 20%) and by Priority Research Centers Program through the NRF funded by the MEST (2018R1A6A1A03024003, 20%) and by the MSIT, Korea, under the ITRC support program (IITP-2026-RS-2024-00438430, 20%) and by Basic Science Research Program through the National Research Foundation of Korea(NRF) funded by the Ministry of Education(RS-2025-25431637, 20%), and the regional innovation system & education (RISE)-(Idea Start-up Valley) program through the Gyeongbuk RISE Center, funded by the Ministry of Education (MOE) and the Gyeongsangbuk-do, Republic of Korea(2026-rise-15-105, 20%)
```
