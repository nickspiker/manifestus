# BLAKE3 Hybrid Incremental Hashing for VSF-DB

## Overview

VSF-DB uses adaptive hashing: small sections get simple BLAKE3 hashes, large sections get incremental Merkle trees. Automatic threshold-based selection provides optimal performance across all data sizes.

---

## Strategy

### Threshold-Based Decision

```rust
const CHUNK_THRESHOLD: usize = 10 * 1024 * 1024;  // 10 MB

if section_size < CHUNK_THRESHOLD {
    // Small section: hash entire section
    hash = BLAKE3(section_data)
} else {
    // Large section: build incremental tree
    tree = Blake3Tree::build(section_data)
    hash = tree.root_hash
}
```

**Small sections (< 10 MB):**
- Pointer array (~1 MB)
- Schema (~10 KB)
- Small indexes (~1 MB)
- → Single BLAKE3 hash

**Large sections (≥ 10 MB):**
- User data (100 GB+)
- Large indexes (50 MB+)
- → Incremental Merkle tree

---

## File Structure

### Hash Manifest

```rust
[dHashManifest
  // Small sections - direct hash
  (lpointers:h{BLAKE3}{hash})
  (lschema:h{BLAKE3}{hash})
  (lindex_age:h{BLAKE3}{hash})
  
  // Large sections - tree reference
  (lusers:t{tree_users})        // References tree section by name
  (lorders:t{tree_orders})
  
  // Combined root
  (lroot:h{BLAKE3}{root_hash})
]
```

### Tree Sections (for large sections only)

```rust
[dBlake3Tree_users
  (lfile_size:u6{bytes})
  (lchunk_size:u4{1024})
  
  // Sparse chunk storage - only modified chunks
  (lchunks:[
    (u6{chunk_id}:h{BLAKE3}{hash})
    (u6{chunk_id}:h{BLAKE3}{hash})
    ...
  ])
  
  // Sparse tree nodes - only computed paths
  (llevel_1:[(u6{node_id}:h{...})...])
  (llevel_2:[(u6{node_id}:h{...})...])
  ...
  
  (lroot:h{BLAKE3}{root})
]

[dBlake3Tree_orders
  ...
]
```

### VSF Header

```
Rå
  b?{header_length}
  hp{31}{manifest_root}   ← Points to HashManifest root
  hm{ref}{manifest}       ← Reference to HashManifest section
  ge{64}{signature}       ← Signs manifest_root
  ...
>
```

---

## Core Data Structures

### Hash Manifest

```rust
struct HashManifest {
    // Section name → hash strategy
    sections: HashMap<String, SectionHash>,
    root_hash: Hash,
}

enum SectionHash {
    Direct(Hash),           // Small section: single hash
    Tree(String),           // Large section: tree section name
}
```

### BLAKE3 Tree (for large sections)

```rust
struct Blake3Tree {
    chunk_size: usize,      // Always 1024 bytes
    file_size: u64,
    
    // Sparse storage - only modified chunks
    chunk_hashes: HashMap<u64, Hash>,
    
    // Sparse tree levels - only computed nodes
    tree_levels: Vec<HashMap<u64, Hash>>,
    
    root_hash: Hash,
}
```

---

## Operations

### Building Initial Hashes

```rust
impl Database {
    fn build_hash_manifest(&mut self) -> Result<HashManifest> {
        let mut manifest = HashManifest::new();
        
        for (name, section_data) in &self.sections {
            if section_data.len() < CHUNK_THRESHOLD {
                // Small section: direct hash
                let hash = blake3::hash(section_data);
                manifest.add_direct(name, hash);
            } else {
                // Large section: build tree
                let tree = Blake3Tree::build(section_data);
                let tree_name = format!("Blake3Tree_{}", name);
                
                self.trees.insert(tree_name.clone(), tree.clone());
                manifest.add_tree(name, tree_name, tree.root_hash);
            }
        }
        
        // Compute manifest root
        manifest.compute_root();
        
        Ok(manifest)
    }
}
```

### Updating on Write

```rust
impl Database {
    fn update_section(&mut self, section_name: &str, offset: u64, data: &[u8]) -> Result<()> {
        // 1. Write data to file
        self.write_at(section_offset + offset, data)?;
        
        // 2. Update hash based on strategy
        match self.manifest.get_strategy(section_name)? {
            SectionHash::Direct(_) => {
                // Small section: rehash entire section
                let section_data = self.read_section(section_name)?;
                let new_hash = blake3::hash(&section_data);
                self.manifest.update_direct(section_name, new_hash);
            }
            
            SectionHash::Tree(tree_name) => {
                // Large section: incremental tree update
                let tree = self.trees.get_mut(&tree_name)
                    .ok_or("Tree not found")?;
                
                tree.update_range(offset, data)?;
                self.manifest.update_tree(section_name, tree.root_hash);
            }
        }
        
        // 3. Recompute manifest root
        self.manifest.compute_root();
        
        // 4. Write updated manifest and trees
        self.write_manifest()?;
        
        Ok(())
    }
}
```

### Tree Update (Incremental)

```rust
impl Blake3Tree {
    fn update_range(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        // 1. Determine affected chunks
        let start_chunk = offset / 1024;
        let end_chunk = (offset + data.len() as u64) / 1024;
        
        // 2. Rehash affected chunks
        for chunk_id in start_chunk..=end_chunk {
            let chunk_data = self.read_chunk(chunk_id)?;
            let hash = blake3::hash(&chunk_data);
            self.chunk_hashes.insert(chunk_id, hash);
        }
        
        // 3. Update tree path to root (O(log n))
        self.recompute_path(start_chunk, end_chunk)?;
        
        Ok(())
    }
    
    fn recompute_path(&mut self, start_chunk: u64, end_chunk: u64) -> Result<()> {
        let height = (self.file_size as f64 / 1024.0).log2().ceil() as usize;
        let mut current_nodes: Vec<u64> = (start_chunk..=end_chunk).collect();
        
        // Bottom-up tree update
        for level in 0..height {
            let mut next_nodes = Vec::new();
            
            for &node_id in &current_nodes {
                let parent_id = node_id / 2;
                
                // Get sibling
                let sibling_id = if node_id % 2 == 0 { node_id + 1 } else { node_id - 1 };
                
                let left_hash = self.get_hash(level, node_id.min(sibling_id))?;
                let right_hash = self.get_hash(level, node_id.max(sibling_id))?;
                
                // Compute parent
                let parent_hash = blake3::hash(&[left_hash.as_bytes(), right_hash.as_bytes()].concat());
                
                self.tree_levels[level + 1].insert(parent_id, parent_hash);
                next_nodes.push(parent_id);
            }
            
            current_nodes = next_nodes;
        }
        
        // Update root
        self.root_hash = self.tree_levels[height].get(&0)
            .copied()
            .ok_or("Root not found")?;
        
        Ok(())
    }
}
```

### Manifest Root Computation

```rust
impl HashManifest {
    fn compute_root(&mut self) {
        // Combine all section hashes
        let mut hasher = blake3::Hasher::new();
        
        // Sort section names for deterministic ordering
        let mut names: Vec<_> = self.sections.keys().collect();
        names.sort();
        
        for name in names {
            let hash = match &self.sections[name] {
                SectionHash::Direct(h) => h,
                SectionHash::Tree(_) => {
                    // Get tree root from tree section
                    self.get_tree_root(name)?
                }
            };
            
            hasher.update(hash.as_bytes());
        }
        
        self.root_hash = hasher.finalize().into();
    }
}
```

---

## Size Transitions

### Section Grows Past Threshold

```rust
impl Database {
    fn check_size_transition(&mut self, section_name: &str) -> Result<()> {
        let section_size = self.get_section_size(section_name)?;
        let current_strategy = self.manifest.get_strategy(section_name)?;
        
        match (current_strategy, section_size >= CHUNK_THRESHOLD) {
            // Grew past threshold: convert to tree
            (SectionHash::Direct(_), true) => {
                let section_data = self.read_section(section_name)?;
                let tree = Blake3Tree::build(&section_data);
                let tree_name = format!("Blake3Tree_{}", section_name);
                
                self.trees.insert(tree_name.clone(), tree.clone());
                self.manifest.convert_to_tree(section_name, tree_name, tree.root_hash);
            }
            
            // Shrunk below threshold: convert to direct
            (SectionHash::Tree(tree_name), false) => {
                let section_data = self.read_section(section_name)?;
                let hash = blake3::hash(&section_data);
                
                self.manifest.convert_to_direct(section_name, hash);
                self.trees.remove(&tree_name);
            }
            
            _ => {} // No transition needed
        }
        
        Ok(())
    }
}
```

---

## Verification

### Full Verification

```rust
impl Database {
    fn verify_full(&self) -> Result<bool> {
        let mut manifest = HashManifest::new();
        
        // Recompute all section hashes
        for (name, section) in &self.sections {
            if section.data.len() < CHUNK_THRESHOLD {
                let hash = blake3::hash(&section.data);
                manifest.add_direct(name, hash);
            } else {
                let tree = Blake3Tree::build(&section.data);
                manifest.add_tree(name, tree.root_hash);
            }
        }
        
        manifest.compute_root();
        
        Ok(manifest.root_hash == self.manifest.root_hash)
    }
}
```

### Incremental Verification

```rust
impl Database {
    fn verify_incremental(&self) -> Result<bool> {
        // Verify only modified chunks in trees
        for tree in self.trees.values() {
            for (&chunk_id, &stored_hash) in &tree.chunk_hashes {
                let chunk_data = self.read_chunk(chunk_id)?;
                let computed = blake3::hash(&chunk_data);
                
                if computed != stored_hash {
                    return Ok(false);
                }
            }
        }
        
        // Recompute manifest root from stored hashes
        let mut test_manifest = self.manifest.clone();
        test_manifest.compute_root();
        
        Ok(test_manifest.root_hash == self.manifest.root_hash)
    }
}
```

---

## Performance Characteristics

### Small Section Update (< 10 MB)
```
Cost: O(section_size)
Example: 1 MB section = hash 1 MB
Time: ~0.3ms (BLAKE3 at 3 GB/s)
```

### Large Section Update (≥ 10 MB)
```
Cost: O(affected_chunks + log file_size)
Example: Update 4KB in 100 GB section
  - Rehash 4 chunks = 4KB
  - Update 27 tree levels = ~1KB
  - Total: ~5KB hashing
Time: ~0.001ms

vs rehashing entire section: 100 GB / 3 GB/s = 33 seconds
Speedup: 33,000,000x faster!
```

### Space Overhead

**Small sections:**
```
Overhead: 32 bytes per section
```

**Large sections (sparse):**
```
Overhead: modified_chunks × 40 bytes
Example: 100 GB, 1% modified = 1M chunks × 40 bytes = 40 MB
Ratio: 0.04% overhead
```

---

## Implementation Phases

### Phase 1: Hash Manifest (Week 1-2)
- [ ] HashManifest structure
- [ ] Section size detection
- [ ] Direct hash for small sections
- [ ] Root computation from section hashes

### Phase 2: Tree Infrastructure (Week 3-4)
- [ ] Blake3Tree structure
- [ ] Sparse chunk storage
- [ ] Tree level computation
- [ ] Root computation from chunks

### Phase 3: Incremental Updates (Week 5-6)
- [ ] update_range() for trees
- [ ] Path recomputation algorithm
- [ ] Manifest update on write
- [ ] Tree persistence

### Phase 4: Size Transitions (Week 7)
- [ ] Threshold monitoring
- [ ] Direct → Tree conversion
- [ ] Tree → Direct conversion
- [ ] Automatic strategy adjustment

### Phase 5: Verification (Week 8)
- [ ] Full verification
- [ ] Incremental verification
- [ ] Corruption detection

**Total: ~2 months**

---

## Summary

**Hybrid strategy:**
- Small sections (< 10 MB): Simple BLAKE3 hash
- Large sections (≥ 10 MB): Incremental Merkle tree
- Automatic threshold-based selection

**Benefits:**
- ✅ Simple for small data
- ✅ Efficient for large data  
- ✅ Automatic adaptation
- ✅ O(log n) updates for large sections
- ✅ Maintains VSF's integrity guarantees

**Enables VSF-DB to scale from kilobytes to terabytes with optimal hashing strategy at every size.** 🎯

---

**END OF SPECIFICATION**