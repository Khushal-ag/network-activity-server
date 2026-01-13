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
    "status": "confirmed"
  },
  {
    "id": "transaction_id_2",
    "tx_result": {
      "signatures": ["signature3"]
    },
    "sent_at": "2024-01-01T11:00:00Z",
    "status": "pending"
  }
]
```

**Response Fields:**
- `id` (string): Transaction identifier
- `tx_result` (object): Transaction result containing:
  - `signatures` (array of strings): Transaction signatures
- `sent_at` (string): ISO 8601 timestamp when transaction was sent
- `status` (string): Transaction status

**Status Codes:**
- `200 OK`: Successfully retrieved transactions
- `500 Internal Server Error`: Database or server error

**Notes:**
- Returns up to 10 most recent transactions
- Transactions are sorted by `sent_at` in descending order (newest first)
- Returns empty array `[]` if no transactions are found
