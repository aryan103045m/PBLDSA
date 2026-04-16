# Fraud Detection Data Handling System

> A streaming, rule-based fraud detection engine written in pure C — no ML, no external libraries. Five core data structures, four fraud rules, O(1) amortised per-transaction latency.

**Author:** Aryan Rajput · Roll No. 0251CSE023  
**Course:** Data Structures and Algorithms – I · NIET, IT Dept  
**Build:** `gcc -o fraud_detection fraud_detection.c -lm`

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [CSV Input Format](#csv-input-format)
- [Architecture & Data Structures](#architecture--data-structures)
- [Fraud Detection Rules](#fraud-detection-rules)
- [Algorithm Complexity](#algorithm-complexity)
- [Configuration](#configuration)
- [Interactive Mode](#interactive-mode)
- [Sample Output](#sample-output)
- [Design Decisions](#design-decisions)
- [Known Limitations & Future Work](#known-limitations--future-work)

---

## Overview

This system processes banking transactions one-by-one (streaming) and applies four fraud rules using only fundamental data structures: hash tables, a circular queue, a sorted array, a linked list, and a stack. No machine learning, no third-party dependencies — just `<stdio.h>`, `<stdlib.h>`, `<math.h>`, and algorithmic reasoning.

The goal is to show that effective fraud detection can be built on pure algorithmic foundations, and that correct data structure selection has measurable impact on latency and memory.

---

## Features

- **Four fraud rules:** high-value transaction, velocity fraud, geographic anomaly, blacklisted merchant
- **CSV-driven:** load accounts, merchants, and transaction streams from files; falls back to built-in seed data if CSVs are missing
- **Interactive menu:** manually enter transactions, add accounts/merchants, blacklist merchants, undo admin actions, view alert log, trigger batch sort
- **Batch forensic analysis:** merge-sort all processed transactions by amount (descending, stable) for post-hoc review
- **Admin undo stack:** last-in-first-out reversal of flagged actions
- **Zero external dependencies:** compiles with a single `gcc` command

---

## Project Structure

```
PBLDSA-main/
├── fraud_detection.c      # Entire system — ~700 lines of annotated C
├── fraud_detection        # Pre-built binary (Linux x86-64)
├── accounts.csv           # Seed accounts: account_id, threshold, lat, lon
├── merchants.csv          # Seed merchants: merchant_id, risk_level
├── transactions.csv       # Demo transaction stream
└── .vscode/
    └── launch.json        # VS Code debug configuration
```

---

## Quick Start

### Prerequisites

- GCC (any modern version) with `-lm` support
- Linux / macOS / WSL (Windows Subsystem for Linux)

### Build

```bash
gcc -o fraud_detection fraud_detection.c -lm
```

### Run (CSV-driven demo)

Place `accounts.csv`, `merchants.csv`, and `transactions.csv` in the same directory as the binary, then:

```bash
./fraud_detection
```

The system loads all three CSVs, processes every transaction, prints per-transaction decisions, dumps the alert log, shows the top-10 batch sort, pops the last 3 undo entries, then offers to enter interactive mode.

### Run (no CSVs needed)

Delete or rename the CSV files. The system detects missing files and falls back to built-in seed data (5 accounts, 5 merchants, 10 demo transactions) automatically.

---

## CSV Input Format

All files are comma-separated with a single header row. Lines beginning with `#` and blank lines are ignored.

### `accounts.csv`

| Column | Type | Description |
|---|---|---|
| `account_id` | string (≤31 chars) | Unique account identifier |
| `threshold` | float | High-value alert threshold in USD |
| `lat` | float | Home latitude (decimal degrees) |
| `lon` | float | Home longitude (decimal degrees) |

```csv
account_id,threshold,lat,lon
ACC001,3000.0,28.6139,77.2090
ACC002,5000.0,19.0760,72.8777
```

### `merchants.csv`

| Column | Type | Description |
|---|---|---|
| `merchant_id` | string (≤31 chars) | Unique merchant identifier |
| `risk_level` | string | `low` / `medium` / `high` / `blacklist` |

Merchants with `risk_level = blacklist` are automatically inserted into the sorted blacklist array at load time.

```csv
merchant_id,risk_level
MER001,low
MER_FRAUD,blacklist
```

### `transactions.csv`

| Column | Type | Description |
|---|---|---|
| `txn_id` | string (≤31 chars) | Unique transaction ID |
| `account_id` | string | Must match an entry in accounts |
| `merchant_id` | string | Must match an entry in merchants |
| `amount` | float | Transaction amount in USD |
| `ts_offset` | long (seconds) | Added to `time(NULL)` at startup — keeps demo timestamps relative |
| `lat` | float | Transaction location latitude |
| `lon` | float | Transaction location longitude |
| `has_location` | int | `1` if lat/lon are valid, `0` to skip geo check |

```csv
txn_id,account_id,merchant_id,amount,ts_offset,lat,lon,has_location
T001,ACC001,MER001,500.0,0,28.6139,77.2090,1
T009,ACC001,MER001,300.0,120,51.5074,-0.1278,1
```

> **Note on `ts_offset`:** T009 above arrives 120 seconds after T001 but from London (~6,700 km away) — this triggers the geographic anomaly rule.

---

## Architecture & Data Structures

### 1. Hash Table — Account & Merchant Lookup

Two separate chained hash tables (size 2003, djb2 hash) store account records and merchant risk levels.

```
account_table[hash(account_id)] → AccountNode → AccountNode → NULL
```

- **Lookup:** O(1) average, O(n) worst-case (load factor kept below 0.75 in practice)
- **Insert:** O(1) average
- **Why not a balanced tree?** No range queries needed; average O(1) dominates O(log n) at streaming throughput. Memory saving: ~16 bytes/entry vs `std::map`.

### 2. Circular Queue — Velocity Sliding Window

Each `AccountRecord` embeds a fixed-capacity circular queue (`vel_queue[MAX_VELOCITY]`) of recent transaction timestamps.

```c
typedef struct {
    time_t vel_queue[MAX_VELOCITY];  // ring buffer
    int    vel_head, vel_tail, vel_count;
} AccountRecord;
```

- **Enqueue:** O(1) — overwrite oldest slot if full
- **Dequeue (eviction):** O(1) amortised — each timestamp is enqueued and dequeued at most once across all transactions
- **Why circular array over `deque`?** Avoids heap allocation per account; memory is bounded and contiguous.

### 3. Sorted Array — Blacklist with Binary Search

```c
char blacklist[MAX_BLACKLIST][ID_LEN];   // kept sorted
int  blacklist_size;
```

Insertion uses an insertion-sort step; lookup uses classic binary search.

- **Lookup:** O(log m) — m=100 max, so ≤7 comparisons
- **Why not a hash set?** Blacklist is small and stable; sorted array has better cache locality for small m, and demonstrates binary search algorithm explicitly.

### 4. Linked List — Append-Only Alert Log

```c
Alert *alert_head, *alert_tail;
```

Tail pointer makes every append O(1) without traversal. Alerts are never deleted during a run.

- **Append:** O(1)
- **Traversal:** O(k), k = alert count — acceptable since this is an offline review operation

### 5. Stack — Admin Undo Buffer

```c
StackNode *admin_top;
```

Every fraud flag pushes `("FLAG_TXN", txn_id)` onto the stack. LIFO semantics match "undo most recent action" exactly.

- **Push / Pop:** O(1)

---

## Fraud Detection Rules

Rules are evaluated in order for every transaction. A transaction can trigger multiple rules.

### Rule 1 — Blacklisted Merchant

```
Binary search blacklist[] for merchant_id → O(log m)
```

Fires if the merchant is in the sorted blacklist. The blacklist is populated from `merchants.csv` (any `risk_level = blacklist`) plus manual additions via the interactive menu.

### Rule 2 — High-Value Transaction

```
amount > account.threshold → O(1)
```

Each account has a configurable threshold loaded from `accounts.csv`. Unknown accounts are auto-inserted with a default threshold of $5,000.

### Rule 3 — Velocity Fraud

```
transactions in last VELOCITY_WINDOW seconds >= VELOCITY_THRESHOLD → O(1) amortised
```

The sliding window queue is updated on every transaction. Old timestamps (older than 60 s by default) are evicted lazily at check time.

### Rule 4 — Geographic Anomaly

```
(distance_km / elapsed_hours) > 1000 km/h → O(1)
```

Haversine distance between the account's last known location and the current transaction location. If the implied travel speed exceeds 1,000 km/h (faster than a commercial aircraft), the transaction is flagged. Skipped when either location is missing.

---

## Algorithm Complexity

| Operation | Data Structure | Average | Worst | Notes |
|---|---|---|---|---|
| Account lookup | Hash table | O(1) | O(n) | Load factor < 0.5 in demo |
| Merchant lookup | Hash table | O(1) | O(n) | Same table |
| Blacklist check | Binary search | O(log m) | O(log m) | m ≤ 100 |
| Velocity enqueue | Circular queue | O(1) | O(1) | |
| Velocity eviction | Circular queue | O(1)* | O(k) | *Amortised; k = stale entries |
| Alert append | Linked list | O(1) | O(1) | Tail pointer |
| Admin push/pop | Stack | O(1) | O(1) | |
| Batch sort | Merge sort | O(n log n) | O(n log n) | Stable; offline |
| Geo check | Haversine | O(1) | O(1) | Fixed math ops |

**Full pipeline per transaction:** O(1) amortised — every rule except the blacklist check is O(1); O(log m) for blacklist with m ≤ 100 is negligible.

---

## Configuration

All tunable constants are `#define`s at the top of `fraud_detection.c`:

| Constant | Default | Description |
|---|---|---|
| `MAX_ACCOUNTS` | 1000 | Hash table capacity for accounts |
| `MAX_MERCHANTS` | 500 | Hash table capacity for merchants |
| `MAX_BLACKLIST` | 100 | Sorted blacklist array size |
| `MAX_VELOCITY` | 10 | Max timestamps in velocity queue per account |
| `VELOCITY_WINDOW` | 60 | Sliding window duration (seconds) |
| `VELOCITY_THRESHOLD` | 5 | Transactions in window to trigger velocity alert |
| `HASH_SIZE` | 2003 | Hash table bucket count (prime) |
| `MAX_ALERTS` | 10000 | Alert log capacity |
| `MAX_BATCH` | 1000 | Batch buffer size for merge sort |

To change velocity window to 5 minutes:
```c
#define VELOCITY_WINDOW  300
```
Then rebuild: `gcc -o fraud_detection fraud_detection.c -lm`

---

## Interactive Mode

After the CSV demo run, the system prompts to enter interactive mode. Menu options:

```
1.  Process manual transaction       — enter txn_id, account, merchant, amount, location
2.  Add account                      — id, threshold, lat, lon
3.  Add merchant                     — id, risk level
4.  Add to blacklist                 — merchant id (also inserts into merchant table)
5.  View alert log                   — prints full linked list
6.  Run batch sort                   — merge-sorts batch buffer, prints all
7.  Undo last admin action           — pops from undo stack
8.  Load accounts from CSV           — prompts for filename
9.  Load merchants from CSV          — prompts for filename
10. Load & process transactions CSV  — prompts for filename, runs all rules
11. Exit
```

---

## Sample Output

```
╔══════════════════════════════════════════════════╗
║   FRAUD DETECTION SYSTEM — CSV-DRIVEN DEMO       ║
╚══════════════════════════════════════════════════╝

[INIT] Loading data from CSV files...
[CSV] Loaded 5 accounts from accounts.csv
[CSV] Loaded 10 merchants from merchants.csv
[CSV] Loaded 15 transactions from transactions.csv

─── TXN T002 | Acct:ACC001     | Merchant:MER002       | $9999.00 ───
  [ALERT] HIGH VALUE: $9999.00 exceeds threshold $3000.00
  [INFO] Velocity: 2 txn(s) in last 60s
  [RESULT] FRAUD DETECTED

─── TXN T003 | Acct:ACC002     | Merchant:MER_FRAUD     | $200.00 ───
  [ALERT] BLACKLISTED MERCHANT: MER_FRAUD
  [INFO] Velocity: 1 txn(s) in last 60s
  [RESULT] FRAUD DETECTED

─── TXN T009 | Acct:ACC001     | Merchant:MER001        | $300.00 ───
  [INFO] Velocity: 1 txn(s) in last 60s
  [ALERT] GEO ANOMALY: 6739 km in 0.03 hr (201170 km/h)
  [RESULT] FRAUD DETECTED

╔══════════════════════════════════════════════════╗
║         FRAUD ALERT LOG  ( 8 alerts)             ║
╚══════════════════════════════════════════════════╝
[  1] TXN:T002         ACCT:ACC001       AMT:  9999.00  RULE:HIGH_VALUE_TRANSACTION          TIME:2026-03-22 11:30:05
[  2] TXN:T003         ACCT:ACC002       AMT:   200.00  RULE:BLACKLISTED_MERCHANT            TIME:2026-03-22 11:30:10
...

╔══════════════════════════════════════════════════╗
║       BATCH ANALYSIS — Top Transactions          ║
╚══════════════════════════════════════════════════╝
TXN_ID       ACCOUNT      MERCHANT            AMOUNT
─────────────────────────────────────────────────────
T002         ACC001       MER002              9999.00
T014         ACC005       MER007              7500.00
T011         ACC004       MER003              1800.00
...

  Processed 15 transactions | 8 fraud | 8 alerts logged
```

---

## Design Decisions

**Why C?** Explicit memory management, no hidden allocations, and direct access to struct layout make the data structure choices visible and measurable. Every byte of overhead is accounted for in the complexity analysis.

**Why merge sort for batch, not quicksort?** Stability: transactions with equal amounts must maintain chronological order for forensic traceability. Merge sort guarantees O(n log n) worst-case; quicksort degrades to O(n²) on sorted or nearly-sorted input — a real risk if transactions arrive time-ordered.

**Why circular array for velocity, not `malloc`'d nodes?** Each account needs a bounded queue of at most `MAX_VELOCITY` timestamps. A fixed-size ring embedded in the `AccountRecord` struct avoids per-enqueue heap allocation, keeps the queue contiguous in cache, and eliminates the risk of fragmentation across 1M+ accounts.

**Why hash size 2003 (prime)?** Prime bucket counts reduce clustering from hash functions that produce multiples of a common factor, distributing collisions more evenly across the table.

**Fallback seed data:** If CSV files are missing, the system inserts hardcoded accounts and transactions so the demo always runs. This makes the binary self-contained for grading or demo environments without file access.

---

## Known Limitations & Future Work

| Limitation | Production Fix |
|---|---|
| Alert linked list grows unbounded | Circular buffer with time-based eviction (e.g., 30-day window) or archive to database |
| No thread safety | Account-level mutex or lock-free queue for concurrent transaction processing |
| Hash table uses separate chaining with `malloc` per node | Open-addressing with tombstones for better cache locality at scale |
| `ts_offset` is relative to startup `time(NULL)` | Use absolute UTC epoch in production CSVs |
| Velocity queue capped at `MAX_VELOCITY = 10` | Dynamically sized queue, or configurable per account tier |
| No persistent storage | Write alert log and account state to SQLite or flat binary file on exit |
| Geo anomaly speed threshold (1,000 km/h) is a compile-time constant | Make configurable per account, or derive from account's typical travel pattern |

---

## License

Academic project — NIET, IT Department, DSA-I Assignment, 2026.  
Source at: [github.com/aryan105825/PBLDSA](https://github.com/aryan105825/PBLDSA) *(update with actual repo URL)*
