/*
 * fraud_detection.c
 * Fraud Detection Data Handling System
 * Author: Aryan Rajput | Roll No. 0251CSE023
 * NIET, IT Dept | DSA-I Assignment
 *
 * Build: gcc -o fraud_detection fraud_detection.c -lm
 * Run:   ./fraud_detection
 *
 * CSV Input Files (place in same directory):
 *   accounts.csv     — account_id, threshold, lat, lon
 *   merchants.csv    — merchant_id, risk_level
 *   transactions.csv — txn_id, account_id, merchant_id, amount,
 *                      ts_offset, lat, lon, has_location
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* ─────────────────────────── CONSTANTS ─────────────────────────── */
#define MAX_ACCOUNTS       1000
#define MAX_MERCHANTS      500
#define MAX_BLACKLIST      100
#define MAX_VELOCITY       10
#define VELOCITY_WINDOW    60
#define VELOCITY_THRESHOLD 5
#define HASH_SIZE          2003
#define ID_LEN             32
#define NAME_LEN           64
#define MAX_ALERTS         10000
#define MAX_BATCH          1000
#define CSV_LINE_LEN       256

/* ─────────────────────────── CSV FILE PATHS ─────────────────────── */
#define CSV_ACCOUNTS     "accounts.csv"
#define CSV_MERCHANTS    "merchants.csv"
#define CSV_TRANSACTIONS "transactions.csv"

/* ─────────────────────────── STRUCTURES ─────────────────────────── */
typedef struct {
    double lat;
    double lon;
    int    valid;
} Location;

typedef struct {
    char      account_id[ID_LEN];
    double    threshold;
    Location  last_location;
    time_t    last_ts;
    time_t    vel_queue[MAX_VELOCITY];
    int       vel_head;
    int       vel_tail;
    int       vel_count;
    int       active;
} AccountRecord;

typedef struct AccountNode {
    AccountRecord       record;
    struct AccountNode *next;
} AccountNode;

typedef struct MerchantNode {
    char               merchant_id[ID_LEN];
    char               risk_level[16];
    struct MerchantNode *next;
} MerchantNode;

typedef struct Alert {
    char         txn_id[ID_LEN];
    char         account_id[ID_LEN];
    char         rule[64];
    double       amount;
    time_t       ts;
    struct Alert *next;
} Alert;

typedef struct {
    char   txn_id[ID_LEN];
    char   account_id[ID_LEN];
    char   merchant_id[ID_LEN];
    double amount;
    time_t ts;
    double lat;
    double lon;
    int    has_location;
} Transaction;

typedef struct StackNode {
    char            action[NAME_LEN];
    char            detail[NAME_LEN];
    struct StackNode *next;
} StackNode;

/* ─────────────────────────── GLOBALS ─────────────────────────── */
AccountNode  *account_table[HASH_SIZE];
MerchantNode *merchant_table[HASH_SIZE];

char    blacklist[MAX_BLACKLIST][ID_LEN];
int     blacklist_size = 0;

Alert  *alert_head = NULL;
Alert  *alert_tail = NULL;
int     alert_count = 0;

StackNode *admin_top = NULL;

Transaction batch_buf[MAX_BATCH];
int         batch_size = 0;

/* ═════════════════════════ HASH FUNCTION ════════════════════════ */
unsigned int hash_str(const char *s) {
    unsigned int h = 5381;
    while (*s) h = ((h << 5) + h) ^ (unsigned char)*s++;
    return h % HASH_SIZE;
}

/* ═══════════════════ HASH TABLE: ACCOUNTS ══════════════════════ */
AccountRecord *account_lookup(const char *id) {
    unsigned int idx = hash_str(id);
    AccountNode *n = account_table[idx];
    while (n) {
        if (strcmp(n->record.account_id, id) == 0) return &n->record;
        n = n->next;
    }
    return NULL;
}

AccountRecord *account_insert(const char *id, double threshold,
                               double lat, double lon, int has_loc) {
    unsigned int idx = hash_str(id);
    AccountNode *n = malloc(sizeof(AccountNode));
    memset(n, 0, sizeof(AccountNode));
    strncpy(n->record.account_id, id, ID_LEN - 1);
    n->record.threshold           = threshold;
    n->record.last_location.lat   = lat;
    n->record.last_location.lon   = lon;
    n->record.last_location.valid = has_loc;
    n->record.vel_head  = 0;
    n->record.vel_tail  = 0;
    n->record.vel_count = 0;
    n->record.active    = 1;
    n->next = account_table[idx];
    account_table[idx] = n;
    return &n->record;
}

/* ══════════════════ HASH TABLE: MERCHANTS ═══════════════════════ */
void merchant_insert(const char *id, const char *risk) {
    unsigned int idx = hash_str(id);
    MerchantNode *n = malloc(sizeof(MerchantNode));
    strncpy(n->merchant_id, id,   ID_LEN - 1);
    strncpy(n->risk_level,  risk, 15);
    n->next = merchant_table[idx];
    merchant_table[idx] = n;
}

const char *merchant_lookup(const char *id) {
    unsigned int idx = hash_str(id);
    MerchantNode *n = merchant_table[idx];
    while (n) {
        if (strcmp(n->merchant_id, id) == 0) return n->risk_level;
        n = n->next;
    }
    return "unknown";
}

/* ══════════════════ SORTED ARRAY: BLACKLIST ═════════════════════ */
void blacklist_add(const char *merchant_id) {
    if (blacklist_size >= MAX_BLACKLIST) return;
    strncpy(blacklist[blacklist_size++], merchant_id, ID_LEN - 1);
    for (int i = blacklist_size - 1; i > 0; i--) {
        if (strcmp(blacklist[i], blacklist[i-1]) < 0) {
            char tmp[ID_LEN];
            strcpy(tmp, blacklist[i]);
            strcpy(blacklist[i], blacklist[i-1]);
            strcpy(blacklist[i-1], tmp);
        } else break;
    }
}

/* Binary search on sorted blacklist — O(log m) */
int blacklist_check(const char *merchant_id) {
    int lo = 0, hi = blacklist_size - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = strcmp(blacklist[mid], merchant_id);
        if (cmp == 0) return 1;
        else if (cmp < 0) lo = mid + 1;
        else              hi = mid - 1;
    }
    return 0;
}

/* ════════════════════ QUEUE: VELOCITY WINDOW ════════════════════ */
void vel_enqueue(AccountRecord *acc, time_t ts) {
    if (acc->vel_count == MAX_VELOCITY) {
        acc->vel_head = (acc->vel_head + 1) % MAX_VELOCITY;
        acc->vel_count--;
    }
    acc->vel_queue[acc->vel_tail] = ts;
    acc->vel_tail = (acc->vel_tail + 1) % MAX_VELOCITY;
    acc->vel_count++;
}

int vel_check(AccountRecord *acc, time_t now) {
    while (acc->vel_count > 0) {
        time_t oldest = acc->vel_queue[acc->vel_head];
        if (difftime(now, oldest) > VELOCITY_WINDOW) {
            acc->vel_head = (acc->vel_head + 1) % MAX_VELOCITY;
            acc->vel_count--;
        } else break;
    }
    vel_enqueue(acc, now);
    return acc->vel_count;
}

/* ══════════════════ LINKED LIST: ALERT LOG ══════════════════════ */
void alert_append(const char *txn_id, const char *acct,
                  const char *rule, double amount, time_t ts) {
    Alert *a = malloc(sizeof(Alert));
    strncpy(a->txn_id,     txn_id, ID_LEN - 1);
    strncpy(a->account_id, acct,   ID_LEN - 1);
    strncpy(a->rule,       rule,   63);
    a->amount = amount;
    a->ts     = ts;
    a->next   = NULL;
    if (!alert_tail) { alert_head = alert_tail = a; }
    else             { alert_tail->next = a; alert_tail = a; }
    alert_count++;
}

void alert_print_all(void) {
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║         FRAUD ALERT LOG  (%3d alerts)             ║\n", alert_count);
    printf("╚══════════════════════════════════════════════════╝\n");
    Alert *cur = alert_head;
    int i = 1;
    while (cur) {
        char timebuf[32];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&cur->ts));
        printf("[%3d] TXN:%-12s ACCT:%-12s AMT:%8.2f  RULE:%-28s  TIME:%s\n",
               i++, cur->txn_id, cur->account_id, cur->amount, cur->rule, timebuf);
        cur = cur->next;
    }
}

/* ══════════════════ STACK: ADMIN UNDO BUFFER ════════════════════ */
void stack_push(const char *action, const char *detail) {
    StackNode *n = malloc(sizeof(StackNode));
    strncpy(n->action, action, NAME_LEN - 1);
    strncpy(n->detail, detail, NAME_LEN - 1);
    n->next   = admin_top;
    admin_top = n;
}

int stack_pop(char *action_out, char *detail_out) {
    if (!admin_top) return 0;
    StackNode *n = admin_top;
    admin_top = n->next;
    strcpy(action_out, n->action);
    strcpy(detail_out, n->detail);
    free(n);
    return 1;
}

/* ══════════════════════ GEO ANOMALY ════════════════════════════ */
#define EARTH_RADIUS_KM 6371.0
static double deg2rad(double d) { return d * 3.14159265358979 / 180.0; }

double haversine_km(double lat1, double lon1, double lat2, double lon2) {
    double dlat = deg2rad(lat2 - lat1);
    double dlon = deg2rad(lon2 - lon1);
    double a = sin(dlat/2)*sin(dlat/2) +
               cos(deg2rad(lat1))*cos(deg2rad(lat2))*sin(dlon/2)*sin(dlon/2);
    return 2 * EARTH_RADIUS_KM * asin(sqrt(a));
}

/* ════════════════════ MERGE SORT: BATCH ════════════════════════ */
void merge(Transaction *arr, int l, int m, int r) {
    int n1 = m - l + 1, n2 = r - m;
    Transaction *L = malloc(n1 * sizeof(Transaction));
    Transaction *R = malloc(n2 * sizeof(Transaction));
    memcpy(L, arr + l,     n1 * sizeof(Transaction));
    memcpy(R, arr + m + 1, n2 * sizeof(Transaction));
    int i = 0, j = 0, k = l;
    while (i < n1 && j < n2) {
        if (L[i].amount > R[j].amount ||
           (L[i].amount == R[j].amount && L[i].ts <= R[j].ts))
            arr[k++] = L[i++];
        else
            arr[k++] = R[j++];
    }
    while (i < n1) arr[k++] = L[i++];
    while (j < n2) arr[k++] = R[j++];
    free(L); free(R);
}

void merge_sort(Transaction *arr, int l, int r) {
    if (l < r) {
        int m = (l + r) / 2;
        merge_sort(arr, l, m);
        merge_sort(arr, m + 1, r);
        merge(arr, l, m, r);
    }
}

/* ════════════════════ CORE: PROCESS TRANSACTION ════════════════ */
typedef enum { OK = 0, FRAUD = 1 } TxnResult;

TxnResult process_transaction(Transaction *t) {
    TxnResult result = OK;
    printf("\n─── TXN %s | Acct:%-10s | Merchant:%-12s | $%.2f ───\n",
           t->txn_id, t->account_id, t->merchant_id, t->amount);

    /* 1. Account lookup — O(1) */
    AccountRecord *acc = account_lookup(t->account_id);
    if (!acc) {
        printf("  [WARN] Unknown account %s — inserting with defaults\n", t->account_id);
        acc = account_insert(t->account_id, 5000.0,
                             t->has_location ? t->lat : 0,
                             t->has_location ? t->lon : 0,
                             t->has_location);
    }

    /* 2. Blacklist check — O(log m) binary search */
    if (blacklist_check(t->merchant_id)) {
        printf("  [ALERT] BLACKLISTED MERCHANT: %s\n", t->merchant_id);
        alert_append(t->txn_id, t->account_id, "BLACKLISTED_MERCHANT", t->amount, t->ts);
        stack_push("FLAG_TXN", t->txn_id);
        result = FRAUD;
    }

    /* 3. Merchant risk level — hash lookup O(1) */
    const char *risk = merchant_lookup(t->merchant_id);
    if (strcmp(risk, "high") == 0)
        printf("  [WARN] High-risk merchant: %s\n", t->merchant_id);

    /* 4. High-value check — O(1) */
    if (t->amount > acc->threshold) {
        printf("  [ALERT] HIGH VALUE: $%.2f exceeds threshold $%.2f\n",
               t->amount, acc->threshold);
        alert_append(t->txn_id, t->account_id, "HIGH_VALUE_TRANSACTION", t->amount, t->ts);
        stack_push("FLAG_TXN", t->txn_id);
        result = FRAUD;
    }

    /* 5. Velocity check — O(1) amortised */
    int vel = vel_check(acc, t->ts);
    printf("  [INFO] Velocity: %d txn(s) in last %ds\n", vel, VELOCITY_WINDOW);
    if (vel >= VELOCITY_THRESHOLD) {
        printf("  [ALERT] VELOCITY FRAUD: %d transactions in %ds window\n",
               vel, VELOCITY_WINDOW);
        alert_append(t->txn_id, t->account_id, "VELOCITY_FRAUD", t->amount, t->ts);
        stack_push("FLAG_TXN", t->txn_id);
        result = FRAUD;
    }

    /* 6. Geographic anomaly check — O(1) */
    if (t->has_location && acc->last_location.valid && acc->last_ts > 0) {
        double dist_km  = haversine_km(acc->last_location.lat, acc->last_location.lon,
                                        t->lat, t->lon);
        double elapsed_h = difftime(t->ts, acc->last_ts) / 3600.0;
        if (elapsed_h > 0 && (dist_km / elapsed_h) > 1000.0) {
            printf("  [ALERT] GEO ANOMALY: %.0f km in %.2f hr (%.0f km/h)\n",
                   dist_km, elapsed_h, dist_km / elapsed_h);
            alert_append(t->txn_id, t->account_id, "GEO_ANOMALY", t->amount, t->ts);
            stack_push("FLAG_TXN", t->txn_id);
            result = FRAUD;
        }
    }

    /* Update last known state */
    if (t->has_location) {
        acc->last_location.lat   = t->lat;
        acc->last_location.lon   = t->lon;
        acc->last_location.valid = 1;
    }
    acc->last_ts = t->ts;

    /* Add to batch buffer */
    if (batch_size < MAX_BATCH)
        batch_buf[batch_size++] = *t;

    printf("  [RESULT] %s\n", result == OK ? "OK" : "FRAUD DETECTED");
    return result;
}

/* ══════════════════════ CSV LOADERS ════════════════════════════ */

/*
 * Strip trailing \r and \n from a string in-place.
 */
static void strip_crlf(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == '\r' || s[len-1] == '\n'))
        s[--len] = '\0';
}

/*
 * load_accounts_csv()
 * Format: account_id,threshold,lat,lon
 * First line is header — skipped.
 * Merchants whose risk_level is "blacklist" are also added to the blacklist array.
 */
int load_accounts_csv(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "[CSV] Cannot open %s\n", filename);
        return 0;
    }
    char line[CSV_LINE_LEN];
    int count = 0;
    int first = 1;
    while (fgets(line, sizeof(line), fp)) {
        strip_crlf(line);
        if (first) { first = 0; continue; }   /* skip header */
        if (line[0] == '\0' || line[0] == '#') continue;

        char id[ID_LEN];
        double threshold, lat, lon;
        if (sscanf(line, "%31[^,],%lf,%lf,%lf", id, &threshold, &lat, &lon) == 4) {
            account_insert(id, threshold, lat, lon, 1);
            count++;
        }
    }
    fclose(fp);
    printf("[CSV] Loaded %d accounts from %s\n", count, filename);
    return count;
}

/*
 * load_merchants_csv()
 * Format: merchant_id,risk_level
 * Merchants with risk_level "blacklist" are also inserted into the blacklist array.
 */
int load_merchants_csv(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "[CSV] Cannot open %s\n", filename);
        return 0;
    }
    char line[CSV_LINE_LEN];
    int count = 0;
    int first = 1;
    while (fgets(line, sizeof(line), fp)) {
        strip_crlf(line);
        if (first) { first = 0; continue; }
        if (line[0] == '\0' || line[0] == '#') continue;

        char id[ID_LEN], risk[16];
        if (sscanf(line, "%31[^,],%15s", id, risk) == 2) {
            merchant_insert(id, risk);
            if (strcmp(risk, "blacklist") == 0)
                blacklist_add(id);
            count++;
        }
    }
    fclose(fp);
    printf("[CSV] Loaded %d merchants from %s\n", count, filename);
    return count;
}

/*
 * load_transactions_csv()
 * Format: txn_id,account_id,merchant_id,amount,ts_offset,lat,lon,has_location
 * ts_offset is added to the current epoch time so demo timestamps are relative.
 * Returns number of transactions loaded into out_txns (up to max_txns).
 */
int load_transactions_csv(const char *filename,
                           Transaction *out_txns, int max_txns) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "[CSV] Cannot open %s\n", filename);
        return 0;
    }
    time_t base = time(NULL);
    char line[CSV_LINE_LEN];
    int count = 0;
    int first = 1;
    while (fgets(line, sizeof(line), fp) && count < max_txns) {
        strip_crlf(line);
        if (first) { first = 0; continue; }
        if (line[0] == '\0' || line[0] == '#') continue;

        Transaction t;
        memset(&t, 0, sizeof(t));
        long ts_offset = 0;
        if (sscanf(line, "%31[^,],%31[^,],%31[^,],%lf,%ld,%lf,%lf,%d",
                   t.txn_id, t.account_id, t.merchant_id,
                   &t.amount, &ts_offset,
                   &t.lat, &t.lon, &t.has_location) == 8) {
            t.ts = base + ts_offset;
            out_txns[count++] = t;
        }
    }
    fclose(fp);
    printf("[CSV] Loaded %d transactions from %s\n", count, filename);
    return count;
}

/* ══════════════════════════ DEMO RUN ══════════════════════════ */
void run_demo(void) {
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║   FRAUD DETECTION SYSTEM — CSV-DRIVEN DEMO       ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    /* Load seed data from CSV files */
    printf("\n[INIT] Loading data from CSV files...\n");
    int accts = load_accounts_csv(CSV_ACCOUNTS);
    int merch = load_merchants_csv(CSV_MERCHANTS);

    if (accts == 0 && merch == 0) {
        printf("[INIT] CSV files not found — using built-in seed data.\n");
        /* Fallback seed */
        account_insert("ACC001", 3000.0, 28.6139, 77.2090, 1);
        account_insert("ACC002", 5000.0, 19.0760, 72.8777, 1);
        account_insert("ACC003", 1000.0, 12.9716, 77.5946, 1);
        merchant_insert("MER001", "low");
        merchant_insert("MER002", "medium");
        merchant_insert("MER003", "high");
        merchant_insert("MER004", "low");
        merchant_insert("MER_FRAUD", "blacklist");
        blacklist_add("MER_FRAUD");
        blacklist_add("MER_BAD1");
        blacklist_add("MER_BAD2");
    }

    /* Load and process transactions */
    Transaction txns[MAX_BATCH];
    int n = load_transactions_csv(CSV_TRANSACTIONS, txns, MAX_BATCH);

    if (n == 0) {
        printf("[INIT] No transactions CSV found — using built-in demo set.\n");
        time_t now = time(NULL);
        Transaction fallback[] = {
            {"T001","ACC001","MER001", 500.0,  now,      28.6139, 77.2090, 1},
            {"T002","ACC001","MER002", 9999.0, now+5,    28.6200, 77.2100, 1},
            {"T003","ACC002","MER_FRAUD",200.0,now+10,   19.0760, 72.8777, 1},
            {"T004","ACC003","MER004",  50.0,  now+1,    12.9716, 77.5946, 1},
            {"T005","ACC003","MER004",  55.0,  now+5,    12.9716, 77.5946, 1},
            {"T006","ACC003","MER004",  60.0,  now+10,   12.9716, 77.5946, 1},
            {"T007","ACC003","MER004",  45.0,  now+15,   12.9716, 77.5946, 1},
            {"T008","ACC003","MER004",  70.0,  now+20,   12.9716, 77.5946, 1},
            {"T009","ACC001","MER001", 300.0,  now+120,  51.5074, -0.1278, 1},
            {"T010","ACC002","MER001", 150.0,  now+200,  19.0800, 72.8800, 1},
        };
        n = (int)(sizeof(fallback) / sizeof(fallback[0]));
        memcpy(txns, fallback, n * sizeof(Transaction));
    }

    printf("\n[DEMO] Processing %d transactions...\n", n);
    int fraud_count = 0;
    for (int i = 0; i < n; i++) {
        if (process_transaction(&txns[i]) == FRAUD) fraud_count++;
    }

    /* Alert Log */
    alert_print_all();

    /* Batch sort */
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║       BATCH ANALYSIS — Top Transactions           ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    merge_sort(batch_buf, 0, batch_size - 1);
    printf("%-12s %-12s %-14s %10s\n", "TXN_ID", "ACCOUNT", "MERCHANT", "AMOUNT");
    printf("─────────────────────────────────────────────────────\n");
    for (int i = 0; i < batch_size && i < 10; i++) {
        printf("%-12s %-12s %-14s %10.2f\n",
               batch_buf[i].txn_id, batch_buf[i].account_id,
               batch_buf[i].merchant_id, batch_buf[i].amount);
    }

    /* Undo stack */
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║           ADMIN UNDO STACK (last 3)               ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    char act[NAME_LEN], det[NAME_LEN];
    int popped = 0;
    while (popped < 3 && stack_pop(act, det)) {
        printf("  UNDO <- action:%-20s detail:%s\n", act, det);
        popped++;
    }

    printf("\n══════════════════════════════════════════════════════\n");
    printf("  Processed %d transactions | %d fraud | %d alerts logged\n",
           n, fraud_count, alert_count);
    printf("══════════════════════════════════════════════════════\n\n");
}

/* ══════════════════════ INTERACTIVE MENU ══════════════════════ */
void interactive_mode(void) {
    int choice;
    while (1) {
        printf("\n┌──────────────────────────────────────────┐\n");
        printf("│    FRAUD DETECTION SYSTEM — MENU         │\n");
        printf("│  1. Process manual transaction           │\n");
        printf("│  2. Add account                          │\n");
        printf("│  3. Add merchant                         │\n");
        printf("│  4. Add to blacklist                     │\n");
        printf("│  5. View alert log                       │\n");
        printf("│  6. Run batch sort                       │\n");
        printf("│  7. Undo last admin action               │\n");
        printf("│  8. Load accounts from CSV               │\n");
        printf("│  9. Load merchants from CSV              │\n");
        printf("│ 10. Load & process transactions from CSV │\n");
        printf("│ 11. Exit                                 │\n");
        printf("└──────────────────────────────────────────┘\n");
        printf("Choice: ");
        if (scanf("%d", &choice) != 1) break;

        if (choice == 1) {
            Transaction t = {0};
            printf("TXN ID: ");        scanf("%31s", t.txn_id);
            printf("Account ID: ");    scanf("%31s", t.account_id);
            printf("Merchant ID: ");   scanf("%31s", t.merchant_id);
            printf("Amount: ");        scanf("%lf",  &t.amount);
            printf("Lat (0 if n/a): "); scanf("%lf", &t.lat);
            printf("Lon (0 if n/a): "); scanf("%lf", &t.lon);
            t.has_location = (t.lat != 0 || t.lon != 0);
            t.ts = time(NULL);
            process_transaction(&t);

        } else if (choice == 2) {
            char id[ID_LEN]; double thr, lat, lon;
            printf("Account ID: ");    scanf("%31s", id);
            printf("Threshold ($): "); scanf("%lf",  &thr);
            printf("Lat: ");           scanf("%lf",  &lat);
            printf("Lon: ");           scanf("%lf",  &lon);
            account_insert(id, thr, lat, lon, 1);
            printf("Account %s added.\n", id);

        } else if (choice == 3) {
            char id[ID_LEN], risk[16];
            printf("Merchant ID: "); scanf("%31s", id);
            printf("Risk (low/medium/high/blacklist): "); scanf("%15s", risk);
            merchant_insert(id, risk);
            printf("Merchant %s added.\n", id);

        } else if (choice == 4) {
            char id[ID_LEN];
            printf("Merchant ID to blacklist: "); scanf("%31s", id);
            blacklist_add(id);
            merchant_insert(id, "blacklist");
            printf("Merchant %s blacklisted.\n", id);

        } else if (choice == 5) {
            alert_print_all();

        } else if (choice == 6) {
            if (batch_size == 0) { printf("No transactions in batch.\n"); continue; }
            merge_sort(batch_buf, 0, batch_size - 1);
            printf("\n%-12s %-12s %-14s %10s\n","TXN_ID","ACCOUNT","MERCHANT","AMOUNT");
            for (int i = 0; i < batch_size; i++)
                printf("%-12s %-12s %-14s %10.2f\n",
                       batch_buf[i].txn_id, batch_buf[i].account_id,
                       batch_buf[i].merchant_id, batch_buf[i].amount);

        } else if (choice == 7) {
            char act2[NAME_LEN], det2[NAME_LEN];
            if (stack_pop(act2, det2))
                printf("Undone: %s — %s\n", act2, det2);
            else
                printf("Undo stack empty.\n");

        } else if (choice == 8) {
            char fname[128];
            printf("CSV filename [%s]: ", CSV_ACCOUNTS);
            scanf("%127s", fname);
            load_accounts_csv(fname);

        } else if (choice == 9) {
            char fname[128];
            printf("CSV filename [%s]: ", CSV_MERCHANTS);
            scanf("%127s", fname);
            load_merchants_csv(fname);

        } else if (choice == 10) {
            char fname[128];
            printf("CSV filename [%s]: ", CSV_TRANSACTIONS);
            scanf("%127s", fname);
            Transaction txns2[MAX_BATCH];
            int n2 = load_transactions_csv(fname, txns2, MAX_BATCH);
            int fc = 0;
            for (int i = 0; i < n2; i++)
                if (process_transaction(&txns2[i]) == FRAUD) fc++;
            printf("[DONE] %d processed, %d fraud detected.\n", n2, fc);

        } else if (choice == 11) {
            printf("Goodbye.\n");
            break;
        } else {
            printf("Invalid choice.\n");
        }
    }
}

/* ══════════════════════════ MAIN ════════════════════════════ */
int main(void) {
    memset(account_table,  0, sizeof(account_table));
    memset(merchant_table, 0, sizeof(merchant_table));

    run_demo();

    printf("Enter interactive mode? (1=Yes 0=No): ");
    int go; scanf("%d", &go);
    if (go) interactive_mode();

    return 0;
}