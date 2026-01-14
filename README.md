# Network Activity Server API

A RESTful API server that provides network activity data from a Sled database.

## API Usage

### Base URL
```
http://localhost:8000
```

### Endpoints

#### GET `/network-activity`

Returns the 10 most recent transactions from the database, sorted by timestamp (newest first).

**Request:**
```bash
curl http://localhost:8000/network-activity
```

**Response:**
```json
[
  {
    "id": "transaction_id_1",
    "tx_result": {
      "signatures": ["signature1", "signature2"]
    },
    "sent_at": "2024-01-01T12:00:00Z",
    "status": "confirmed",
    "chain": "solana",
    "from_address": "0x1234...",
    "user_key_info": {
      "pubkey": "0x5678...",
      "chain": "solana",
      "created_at": "2024-01-01T10:00:00Z",
      "expires_at": "2024-01-02T10:00:00Z",
      "accumulated_credits": 100
    }
  }
]
```

**Response Fields:**
- `id` (string): Transaction identifier
- `tx_result` (object): Transaction result containing:
  - `signatures` (array of strings): Transaction signatures
  - Additional fields may be present in `tx_result` if they exist in the database
- `sent_at` (string): ISO 8601 timestamp when transaction was sent
- `status` (string): Transaction status (typically "confirmed")
- `chain` (string, optional): Blockchain network - "solana" or "base"
- `from_address` (string, optional): Sender address if available in transaction data
- `user_key_info` (object, optional): Information about the user key used for this transaction:
  - `pubkey` (string): Public key of the user
  - `chain` (string): Blockchain network
  - `created_at` (string): When the user key was created
  - `expires_at` (string): When the user key expires
  - `accumulated_credits` (number): Credits accumulated by this user key

**Status Codes:**
- `200 OK`: Successfully retrieved transactions
- `500 Internal Server Error`: Database or server error

**Notes:**
- Returns up to 10 most recent transactions
- Transactions are sorted by `sent_at` in descending order (newest first)
- Returns empty array `[]` if no transactions are found
