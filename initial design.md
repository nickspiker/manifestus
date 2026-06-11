# VSF-DB: Database Layer Specification

## Overview

A database system built on VSF's storage format, providing query capabilities while leveraging VSF's rich type system, cryptographic verification, and optimal space utilization.

---

## Architecture Layers

```
┌─────────────────────────────────────────┐
│  Query API / SQL Parser                 │  Layer 4: User Interface
├─────────────────────────────────────────┤
│  Query Executor / Join Engine           │  Layer 3: Query Processing
├─────────────────────────────────────────┤
│  Index Manager (HashMap/Bucket/BTree)   │  Layer 2: Access Optimization
├─────────────────────────────────────────┤
│  Pointer Array + Allocation Manager     │  Layer 1: Storage Management
├─────────────────────────────────────────┤
│  VSF Storage Format                     │  Layer 0: Binary Format
└─────────────────────────────────────────┘
```

---

## Layer 0: VSF Storage Format (Already Built)

**What it provides:**
- 211 typed primitives
- Self-describing binary format
- Mandatory BLAKE3 verification
- Section-based organization
- Cryptographic primitives (hashes, signatures, keys)

**File structure:**
```
Rå
  b?{header_length}
  z?{version}
  hp{31}{BLAKE3 hash}
  ge{64}{signature (optional)}
  n?{section_count}
  (dSectionName:h,g,k,o,b,n)...
>
[dSectionName (data...)]
[dSectionName (data...)]
```

---

## Layer 1: Storage Management

### 1.1 Fat Pointer Array

**Core structure:**
```rust
struct FatPointer {
    offset: u64,        // Byte offset in file (8 bytes)
    length: u64,        // Data length in bytes (8 bytes)
    type_marker: u8,    // VSF type marker (1 byte)
    flags: u8,          // Status flags (1 byte)
}
// Total: 18 bytes per pointer

enum PointerFlags {
    Active = 0x01,      // Entry is valid
    Deleted = 0x02,     // Entry marked for deletion (zeroed)
    Indexed = 0x04,     // Entry is indexed
    Signed = 0x08,      // Entry has signature
}

struct PointerArray {
    pointers: Vec<FatPointer>,
    free_list: Vec<usize>,  // Indices of deleted entries
}
```

**Stored in VSF:**
```rust
[dPointerArray
  (lcount:u5{1000})
  (lpointers:t_u3{Tensor of pointer data})  // Raw bytes, 18 bytes each
]
```

### 1.2 Allocation Strategy

**First-fit with type filtering:**
```rust
impl AllocationManager {
    fn allocate(&mut self, data: &[u8], type_marker: u8) -> Result<usize> {
        // 1. Try to reuse deleted entry slot
        if let Some(index) = self.free_list.pop() {
            // Find zero region that fits
            if let Some(offset) = self.find_zero_region(data.len()) {
                self.write_at(offset, data);
                self.pointers[index] = FatPointer {
                    offset,
                    length: data.len() as u64,
                    type_marker,
                    flags: PointerFlags::Active as u8,
                };
                return Ok(index);
            }
        }
        
        // 2. No gap found, append to end
        let offset = self.file_size();
        self.write_at(offset, data);
        let index = self.pointers.len();
        self.pointers.push(FatPointer {
            offset,
            length: data.len() as u64,
            type_marker,
            flags: PointerFlags::Active as u8,
        });
        Ok(index)
    }
    
    fn delete(&mut self, index: usize) -> Result<()> {
        let ptr = &self.pointers[index];
        
        // Zero the data
        self.write_zeros(ptr.offset, ptr.length);
        
        // Mark pointer as deleted
        self.pointers[index].flags = PointerFlags::Deleted as u8;
        
        // Add to free list
        self.free_list.push(index);
        
        Ok(())
    }
    
    fn find_zero_region(&self, needed_size: usize) -> Option<u64> {
        // Scan file for contiguous zeros >= needed_size
        // Start from random offset for even distribution
        // Return first fit
    }
}
```

**Performance characteristics:**
- Average utilization: ~83% (empirically verified)
- Allocation: O(n) worst case (scan for gap), amortized O(1)
- Deletion: O(1) (mark deleted, add to free list)
- No garbage collection required

### 1.3 File Layout

```
┌────────────────────────────────────────┐
│ VSF Header                             │
│   hp{hash}, ge{sig}, etc.              │
└────────────────────────────────────────┘
┌────────────────────────────────────────┐
│ Pointer Array Section                  │
│   [dPointerArray ...]                  │
└────────────────────────────────────────┘
┌────────────────────────────────────────┐
│ Schema Section                         │
│   [dSchema ...]                        │
└────────────────────────────────────────┘
┌────────────────────────────────────────┐
│ Index Sections                         │
│   [dIndex_field1 ...]                  │
│   [dIndex_field2 ...]                  │
└────────────────────────────────────────┘
┌────────────────────────────────────────┐
│ Data Area (pointed to by pointers)     │
│                                        │
│ [Active data]                          │
│ [0000 deleted]                         │
│ [Active data]                          │
│ [0000 deleted]                         │
│ [Active data]                          │
│ ...                                    │
└────────────────────────────────────────┘
```

---

## Layer 2: Index Manager

### 2.1 Index Types

**Hash Index (Exact Match):**
```rust
struct HashIndex {
    name: String,           // e.g., "users_by_email"
    field: String,          // Field being indexed
    map: HashMap<VsfType, Vec<usize>>,  // Value -> pointer indices
}

// Stored in VSF:
[dIndex_users_email
  (lalice@email.com:[n{0},n{5},n{42}])
  (lbob@email.com:[n{1},n{8}])
]
```

**Bucket Index (Range Queries):**
```rust
struct BucketIndex {
    name: String,
    field: String,
    bucket_size: f64,       // e.g., 10.0 for temps in 10° buckets
    buckets: HashMap<i64, Vec<usize>>,  // Bucket ID -> pointer indices
}

// Example: Temperature index with 10° buckets
// 0-10°C = bucket 0
// 10-20°C = bucket 1
// 20-30°C = bucket 2

[dIndex_temperature_bucket
  (lbucket_0:[n{5},n{23},n{67}])     // 0-10°C
  (lbucket_1:[n{12},n{45}])          // 10-20°C
  (lbucket_2:[n{89},n{134},n{201}])  // 20-30°C
]
```

**BTree Index (Advanced, Optional):**
```rust
struct BTreeIndex {
    name: String,
    field: String,
    tree: BTreeMap<VsfType, Vec<usize>>,
}

// For complex range queries when bucket index insufficient
// Adds ~1000 lines of code
// Defer until proven necessary
```

### 2.2 Index Operations

```rust
trait Index {
    fn insert(&mut self, value: &VsfType, pointer_index: usize);
    fn remove(&mut self, value: &VsfType, pointer_index: usize);
    fn lookup(&self, query: &Query) -> Vec<usize>;  // Returns pointer indices
    fn serialize(&self) -> Vec<u8>;  // To VSF section
    fn deserialize(data: &[u8]) -> Self;  // From VSF section
}

impl HashIndex {
    fn lookup(&self, query: &Query) -> Vec<usize> {
        match query {
            Query::Exact(value) => {
                self.map.get(value).cloned().unwrap_or_default()
            }
            _ => vec![],  // Hash index doesn't support ranges
        }
    }
}

impl BucketIndex {
    fn lookup(&self, query: &Query) -> Vec<usize> {
        match query {
            Query::Range(min, max) => {
                let start_bucket = self.value_to_bucket(min);
                let end_bucket = self.value_to_bucket(max);
                
                let mut results = Vec::new();
                for bucket_id in start_bucket..=end_bucket {
                    if let Some(indices) = self.buckets.get(&bucket_id) {
                        results.extend(indices);
                    }
                }
                results
            }
            Query::Exact(value) => {
                let bucket_id = self.value_to_bucket(value);
                self.buckets.get(&bucket_id).cloned().unwrap_or_default()
            }
        }
    }
    
    fn value_to_bucket(&self, value: &VsfType) -> i64 {
        // Extract numeric value and divide by bucket_size
        match value {
            VsfType::f5(f) => (f / self.bucket_size).floor() as i64,
            VsfType::u5(u) => (*u as f64 / self.bucket_size).floor() as i64,
            // ... handle other numeric types
            _ => 0,
        }
    }
}
```

### 2.3 Index Management

```rust
struct IndexManager {
    indexes: HashMap<String, Box<dyn Index>>,
}

impl IndexManager {
    fn create_index(&mut self, 
                    table: &str, 
                    field: &str, 
                    index_type: IndexType) -> Result<()> {
        let name = format!("{}_{}", table, field);
        
        let index: Box<dyn Index> = match index_type {
            IndexType::Hash => Box::new(HashIndex::new(name, field)),
            IndexType::Bucket(size) => Box::new(BucketIndex::new(name, field, size)),
            IndexType::BTree => Box::new(BTreeIndex::new(name, field)),
        };
        
        self.indexes.insert(name, index);
        Ok(())
    }
    
    fn find_best_index(&self, query: &Query) -> Option<&dyn Index> {
        // Query optimizer: pick best index for query
        // Priority: Hash > Bucket > BTree > None (scan)
        
        match query {
            Query::Exact(field, _) => {
                // Look for hash index on this field
                self.indexes.get(&format!("hash_{}", field))
            }
            Query::Range(field, _, _) => {
                // Look for bucket or btree index
                self.indexes.get(&format!("bucket_{}", field))
                    .or_else(|| self.indexes.get(&format!("btree_{}", field)))
            }
        }
    }
}
```

---

## Layer 3: Query Processing

### 3.1 Schema Definition

```rust
struct Schema {
    tables: HashMap<String, TableSchema>,
}

struct TableSchema {
    name: String,
    fields: Vec<FieldSchema>,
    primary_key: Option<String>,
}

struct FieldSchema {
    name: String,
    vsf_type: VsfTypeMarker,  // Which VSF type (u5, f6, x, etc.)
    nullable: bool,
    indexed: bool,
}

// Stored in VSF:
[dSchema
  (ltable:x{"users"})
  (lfields:[
    (lname:x{"id"},ltype:x{"u5"},lnullable:u0{false},lprimary:u0{true})
    (lname:x{"name"},ltype:x{"x"},lnullable:u0{false})
    (lname:x{"email"},ltype:x{"x"},lnullable:u0{false})
    (lname:x{"age"},ltype:x{"u3"},lnullable:u0{true})
  ])
]
```

### 3.2 Record Structure

**Row as VSF section:**
```rust
// Each record stored as labeled fields
[dRecord_0
  (lid:u5{1})
  (lname:x{"Alice"})
  (lemail:x{"alice@email.com"})
  (lage:u3{30})
]

// Or more compactly, as tuple:
[dRecord_0 (u5{1},x{"Alice"},x{"alice@email.com"},u3{30})]
```

**Pointer array points to these records:**
```rust
FatPointer {
    offset: 5000,      // Location of [dRecord_0 ...]
    length: 150,       // Size of record
    type_marker: b'd', // Section type
    flags: Active,
}
```

### 3.3 Query Language

**Option A: SQL-like (if ambitious):**
```sql
SELECT name, age FROM users WHERE age > 25 AND city = 'Seattle'
```

**Option B: Builder API (simpler to implement):**
```rust
db.table("users")
  .select(&["name", "age"])
  .filter("age", Filter::GreaterThan(VsfType::u3(25)))
  .filter("city", Filter::Equals(VsfType::x("Seattle".into())))
  .execute()?
```

**Option C: Functional API:**
```rust
db.query("users")
  .filter(|record| {
      record.get("age")? > 25 && record.get("city")? == "Seattle"
  })
  .select(&["name", "age"])
  .execute()?
```

### 3.4 Query Execution

```rust
struct QueryExecutor {
    pointer_array: PointerArray,
    index_manager: IndexManager,
    schema: Schema,
}

impl QueryExecutor {
    fn execute(&self, query: &Query) -> Result<Vec<Record>> {
        // 1. Query planning
        let plan = self.plan_query(query)?;
        
        // 2. Get candidate pointer indices
        let indices = match plan.index {
            Some(index) => index.lookup(&query),  // Use index
            None => self.scan_all(query),         // Full scan with type filter
        };
        
        // 3. Read records from disk
        let mut results = Vec::new();
        for idx in indices {
            let ptr = &self.pointer_array.pointers[idx];
            
            // Skip deleted entries
            if ptr.flags & PointerFlags::Deleted != 0 {
                continue;
            }
            
            let record = self.read_record(ptr)?;
            
            // Apply filters (for bucket index, still need to filter within bucket)
            if query.matches(&record) {
                results.push(record);
            }
        }
        
        // 4. Apply ordering, limit, etc.
        self.apply_modifiers(&mut results, query)?;
        
        Ok(results)
    }
    
    fn scan_all(&self, query: &Query) -> Vec<usize> {
        // Type-filtered scan (happens in RAM!)
        self.pointer_array.pointers.iter()
            .enumerate()
            .filter(|(_, ptr)| {
                // Skip deleted
                if ptr.flags & PointerFlags::Deleted != 0 {
                    return false;
                }
                
                // Type filter (free in RAM!)
                match query.expected_type() {
                    Some(t) if ptr.type_marker != t => false,
                    _ => true,
                }
            })
            .map(|(i, _)| i)
            .collect()
    }
}
```

### 3.5 Join Implementation

```rust
enum JoinType {
    Inner,
    Left,
    Right,
    Full,
}

struct Join {
    left_table: String,
    right_table: String,
    left_field: String,
    right_field: String,
    join_type: JoinType,
}

impl QueryExecutor {
    fn execute_join(&self, join: &Join) -> Result<Vec<Record>> {
        // Hash join algorithm (most common)
        
        // 1. Build hash table from left side
        let left_records = self.scan_table(&join.left_table)?;
        let mut hash_table: HashMap<VsfType, Vec<Record>> = HashMap::new();
        
        for record in left_records {
            let key = record.get(&join.left_field)?;
            hash_table.entry(key).or_insert(Vec::new()).push(record);
        }
        
        // 2. Probe with right side
        let right_records = self.scan_table(&join.right_table)?;
        let mut results = Vec::new();
        
        for right_record in right_records {
            let key = right_record.get(&join.right_field)?;
            
            if let Some(left_matches) = hash_table.get(&key) {
                // Match found
                for left_record in left_matches {
                    results.push(self.merge_records(left_record, &right_record));
                }
            } else if matches!(join.join_type, JoinType::Right | JoinType::Full) {
                // Right/Full join: include unmatched right records with nulls
                results.push(self.merge_with_nulls(None, Some(&right_record)));
            }
        }
        
        // Handle left/full join unmatched records
        if matches!(join.join_type, JoinType::Left | JoinType::Full) {
            // ... add unmatched left records with nulls
        }
        
        Ok(results)
    }
}
```

---

## Layer 4: Transaction Management

### 4.1 Transaction Structure

```rust
struct Transaction {
    id: u64,
    start_time: EagleTime,
    
    // Copy-on-write: backup of pointers before modification
    original_pointers: Vec<FatPointer>,
    modified_indices: HashSet<usize>,
    
    // Write-ahead log
    operations: Vec<Operation>,
}

enum Operation {
    Insert { index: usize, data: Vec<u8> },
    Update { index: usize, old_data: Vec<u8>, new_data: Vec<u8> },
    Delete { index: usize, data: Vec<u8> },
}

impl Transaction {
    fn begin(db: &Database) -> Self {
        Transaction {
            id: db.next_transaction_id(),
            start_time: EagleTime::now(),
            original_pointers: db.pointer_array.pointers.clone(),
            modified_indices: HashSet::new(),
            operations: Vec::new(),
        }
    }
    
    fn insert(&mut self, table: &str, record: Record) -> Result<()> {
        let data = record.serialize()?;
        let index = self.allocate(data)?;
        
        self.operations.push(Operation::Insert { index, data });
        self.modified_indices.insert(index);
        
        Ok(())
    }
    
    fn commit(&mut self, db: &mut Database) -> Result<()> {
        // 1. Write operations to WAL (write-ahead log)
        let wal_entry = WalEntry {
            transaction_id: self.id,
            operations: self.operations.clone(),
            timestamp: EagleTime::now(),
        };
        
        db.write_wal(wal_entry)?;
        
        // 2. Apply changes to main database
        for op in &self.operations {
            match op {
                Operation::Insert { index, data } => {
                    db.write_record(*index, data)?;
                }
                Operation::Update { index, new_data, .. } => {
                    db.update_record(*index, new_data)?;
                }
                Operation::Delete { index, .. } => {
                    db.delete_record(*index)?;
                }
            }
        }
        
        // 3. Update indexes
        db.update_indexes(&self.operations)?;
        
        // 4. Mark WAL entry as committed
        db.mark_wal_committed(self.id)?;
        
        Ok(())
    }
    
    fn rollback(&mut self, db: &mut Database) -> Result<()> {
        // Restore original pointer array
        db.pointer_array.pointers = self.original_pointers.clone();
        
        // Clear WAL entry
        db.clear_wal(self.id)?;
        
        Ok(())
    }
}
```

### 4.2 Write-Ahead Log (WAL)

```rust
// Stored as VSF section
[dWAL
  (ltxn_id:u6{1},ltime:ef6{...},loperations:[
    (ltype:x{"insert"},lindex:u5{42},ldata:v{z}{compressed_data})
    (ltype:x{"delete"},lindex:u5{17})
  ])
  (ltxn_id:u6{2},ltime:ef6{...},loperations:[
    (ltype:x{"update"},lindex:u5{5},ldata:v{z}{compressed_data})
  ])
]
```

**Crash recovery:**
```rust
impl Database {
    fn recover_from_crash(&mut self) -> Result<()> {
        // 1. Read WAL
        let wal_entries = self.read_wal()?;
        
        // 2. Find uncommitted transactions
        let uncommitted: Vec<_> = wal_entries.iter()
            .filter(|e| !e.committed)
            .collect();
        
        // 3. Rollback uncommitted transactions
        for entry in uncommitted {
            self.rollback_transaction(entry)?;
        }
        
        // 4. Replay committed transactions that weren't applied
        let committed_unapplied: Vec<_> = wal_entries.iter()
            .filter(|e| e.committed && !e.applied)
            .collect();
            
        for entry in committed_unapplied {
            self.replay_transaction(entry)?;
        }
        
        Ok(())
    }
}
```

### 4.3 ACID Properties

**Atomicity:** Transactions either fully commit or fully rollback
- WAL ensures all-or-nothing
- Rollback restores original pointer array

**Consistency:** Schema constraints enforced
- Type checking via VSF types
- Foreign key checks (if implemented)
- Unique constraints via indexes

**Isolation:** Copy-on-write for concurrent reads
- Readers see snapshot of pointers
- Writers acquire exclusive lock
- Optimistic concurrency control possible

**Durability:** Changes persisted to disk
- WAL written before commit
- fsync() called to flush disk cache
- Crash recovery from WAL

---

## API Design

### High-Level API

```rust
use vsf_db::{Database, Record, Filter};

fn main() -> Result<()> {
    // 1. Create/open database
    let mut db = Database::create("myapp.vsf")?;
    // or
    let mut db = Database::open("myapp.vsf")?;
    
    // 2. Define schema
    db.create_table("users")
        .field("id", VsfType::u5, nullable: false, primary_key: true)
        .field("name", VsfType::x, nullable: false)
        .field("email", VsfType::x, nullable: false)
        .field("age", VsfType::u3, nullable: true)
        .build()?;
    
    // 3. Create indexes
    db.create_index("users", "email", IndexType::Hash)?;
    db.create_index("users", "age", IndexType::Bucket(10.0))?;
    
    // 4. Insert records
    let mut txn = db.begin_transaction()?;
    
    txn.insert("users", Record::new()
        .set("id", VsfType::u5(1))
        .set("name", VsfType::x("Alice".into()))
        .set("email", VsfType::x("alice@email.com".into()))
        .set("age", VsfType::u3(30))
    )?;
    
    txn.commit()?;
    
    // 5. Query
    let results = db.query("users")
        .filter("age", Filter::Range(25, 35))
        .filter("email", Filter::Like("%@email.com"))
        .select(&["name", "email"])
        .order_by("name", Order::Asc)
        .limit(10)
        .execute()?;
    
    for record in results {
        println!("{}: {}", record.get("name")?, record.get("email")?);
    }
    
    // 6. Join
    let joined = db.query("users")
        .join("orders", "id", "user_id", JoinType::Inner)
        .select(&["users.name", "orders.product", "orders.amount"])
        .execute()?;
    
    // 7. Update
    let mut txn = db.begin_transaction()?;
    
    txn.update("users")
        .filter("email", Filter::Equals("alice@email.com"))
        .set("age", VsfType::u3(31))
        .execute()?;
    
    txn.commit()?;
    
    // 8. Delete
    let mut txn = db.begin_transaction()?;
    
    txn.delete("users")
        .filter("age", Filter::LessThan(18))
        .execute()?;
    
    txn.commit()?;
    
    Ok(())
}
```

---

## Performance Characteristics

### Space Efficiency
- **Pointer array overhead:** 18 bytes per record (in RAM)
- **Average utilization:** ~83% (empirically verified)
- **Index overhead:** ~30-50% of data size (varies by cardinality)
- **No page alignment waste:** records use exact space needed

### Time Complexity
- **Insert:** O(n) worst case (scan for gap), amortized O(1)
- **Delete:** O(1) (mark deleted, add to free list)
- **Lookup by index:** 
  - Hash: O(1) average
  - Bucket: O(log b + k) where b = buckets, k = results
  - BTree: O(log n + k)
- **Full scan:** O(n) with type filtering in RAM
- **Join:** O(n + m) for hash join

### Scalability
- **Small datasets (< 100K):** No indexes needed, linear scan is fast
- **Medium datasets (100K - 10M):** Hash + bucket indexes sufficient
- **Large datasets (10M+):** Consider BTree indexes for complex queries

---

## Implementation Phases

### Phase 1: Core Storage (Week 1-2)
- [ ] FatPointer structure
- [ ] PointerArray with serialization
- [ ] First-fit allocation
- [ ] Delete with zeroing
- [ ] Basic file I/O

### Phase 2: Schema & Records (Week 3-4)
- [ ] Schema definition
- [ ] TableSchema structure
- [ ] Record serialization/deserialization
- [ ] Insert/delete operations
- [ ] Basic validation

### Phase 3: Indexes (Week 5-7)
- [ ] HashIndex implementation
- [ ] BucketIndex implementation
- [ ] Index serialization to VSF
- [ ] Index updates on insert/delete
- [ ] Index manager

### Phase 4: Query Engine (Week 8-10)
- [ ] Query structure and parser
- [ ] Query executor
- [ ] Query planner (index selection)
- [ ] Filter evaluation
- [ ] Result projection

### Phase 5: Joins (Week 11-12)
- [ ] Hash join algorithm
- [ ] Inner/left/right/full join types
- [ ] Multi-table queries
- [ ] Join optimization

### Phase 6: Transactions (Week 13-15)
- [ ] Transaction structure
- [ ] Copy-on-write for reads
- [ ] Write-ahead log (WAL)
- [ ] Commit/rollback
- [ ] Crash recovery

### Phase 7: API & Polish (Week 16-18)
- [ ] High-level builder API
- [ ] Error handling
- [ ] Documentation
- [ ] Example applications
- [ ] Benchmarks

### Phase 8: Optimization (Week 19-24)
- [ ] Query caching
- [ ] Index statistics for query planning
- [ ] Bulk insert optimization
- [ ] Concurrent read support
- [ ] Optional BTree index

**Total estimated time: ~6 months** (matching VSF core development)

---

## Open Questions

1. **Concurrency model:** 
   - Single writer, multiple readers (simpler)
   - MVCC for concurrent writes (complex)
   - Start with former, add latter if needed

2. **Query language:**
   - SQL parser (ambitious, ~5K lines)
   - Builder API (simpler, ~1K lines)
   - Start with builder, add SQL later

3. **Foreign keys:**
   - Enforce referential integrity?
   - Adds complexity to insert/delete
   - Defer until schema constraints needed

4. **Triggers/stored procedures:**
   - Out of scope for v1
   - Can add later if needed

5. **Replication/clustering:**
   - Out of scope for v1
   - VSF's crypto primitives enable distributed systems
   - Future work

6. **Full-text search:**
   - Specialized index type
   - Out of scope for v1
   - Can add as separate crate

---

## Advantages Over SQLite

1. **Rich type system:** 211 types vs 5
2. **No size limits:** Arbitrary precision integers, no 2^64 cap
3. **Space efficiency:** 83% utilization vs ~50%
4. **Type filtering:** Query in RAM before disk I/O
5. **Mandatory verification:** BLAKE3 on every file
6. **Crypto primitives:** First-class hashes, signatures, keys
7. **Domain-specific types:** Spirix, Eagle Time, WorldCoord, color spaces
8. **Mixed data sizes:** 8 bytes next to 50MB, no waste

## Trade-offs vs SQLite

1. **Maturity:** SQLite has 25 years of production hardening
2. **Tooling:** No existing admin tools, debuggers, ORMs
3. **Ecosystem:** Must build from scratch
4. **Query optimizer:** SQLite's is highly sophisticated
5. **Concurrency:** SQLite's WAL mode supports multiple readers + single writer

---

## Use Cases

### Ideal for VSF-DB:
- ✅ Photography applications (RAW files + metadata)
- ✅ Scientific data (sensors + measurements + calibration)
- ✅ Financial systems (arbitrary precision, audit trails)
- ✅ Geospatial apps (WorldCoord, precise locations)
- ✅ Medical imaging (DICOM + analysis + signatures)
- ✅ Messaging apps (crypto verification, history)

### SQLite still better for:
- ⚠️ Traditional CRUD apps (established patterns)
- ⚠️ Embedded systems (SQLite is tiny, 600KB)
- ⚠️ When you need existing tools/ORMs
- ⚠️ High concurrency writes

---

## Next Steps

1. **Review this spec:** Identify gaps, clarify questions
2. **Prototype pointer array:** Validate allocation strategy
3. **Design schema format:** Finalize VSF representation
4. **Build query API:** Start with simplest useful interface
5. **Iterate:** Add complexity only when proven necessary

---

**END OF SPECIFICATION**