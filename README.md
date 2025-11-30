# 🚀 XOR-Filter-Enhanced Rabin–Karp (C Implementation)

This repository contains an ongoing implementation of an **XOR Filter** and its integration into an enhanced version of the **Rabin–Karp string-matching algorithm**.

The XOR filter is used as a **pre-processing stage** to eliminate patterns that *definitely do not appear* in the text, reducing unnecessary comparisons during Rabin–Karp.

The project is based on the idea described in the research paper **“Enhancement of Rabin–Karp Algorithm Using XOR Filter”**.

---

## ✅ Current Project Status

### **1. 64-bit Hash Function (FNV-1a) — ✔ Done**
- Fully implemented 64-bit FNV-1a hash.
- Uses raw `uint8_t` bytes (no signedness issues).
- Deterministic, portable, and suitable for substring hashing.
- Correct 64-bit hex printing using `%llX`.

### **2. High-Quality Bit Mixing (SplitMix64) — ✔ Done**
A strong mixing function (`mix64`) is implemented to derive independent hashes with excellent avalanche properties.

### **3. Derivation of 3 Independent Hashes + 8-bit Fingerprint — ✔ Done**
For any key, the program now generates:
- `h0` — mixed hash #1  
- `h1` — mixed hash #2  
- `h2` — mixed hash #3  
- `fp` — 8-bit fingerprint  

These form the **core foundation** for an XOR filter.

---

## ⏳ What Is Not Implemented Yet (To-Do)

### **1. XOR Filter Structure**
Define the main filter storage:

```c
typedef struct {
    uint8_t *fp;       // fingerprint array
    uint32_t capacity; // number of buckets (~1.23 × N)
} xor_filter_t;
```

---

### **2. Filter Initialization**
Tasks:
- Compute capacity ≈ `ceil(1.23 × number_of_keys)`
- Allocate fingerprint array using `calloc`
- Prepare auxiliary arrays for peeling

---

### **3. Preprocessing Keys Before Build**
For each pattern:
1. Compute base hash  
2. Derive `(i0, i1, i2)` using modulo capacity  
3. Store triple + fingerprint in a `xor_key_t` struct  

Example:

```c
typedef struct {
    uint32_t i0, i1, i2;
    uint8_t fp;
} xor_key_t;
```

---

### **4. Peeling Algorithm (Core of XOR Filter)**
Implement the 4-stage construction:

1. **Count degrees**  
2. **Push degree-1 buckets**  
3. **Peel all keys**  
4. **Reverse assignment**  

Goal equation for every key `k`:

```c
F[i0] ^ F[i1] ^ F[i2] == fp
```

---

### **5. Membership Query Implementation**
After construction, check membership with:

```c
bool xor_filter_contains(
    const xor_filter_t *f,
    const uint8_t *key,
    size_t len
);
```

Steps:
1. Derive `(i0, i1, i2, fp)`
2. Compute `F[i0] ^ F[i1] ^ F[i2]`
3. Compare with `fp`

- **Match → maybe present**  
- **No match → definitely not present**

---

### **6. Integration into Rabin–Karp**
After XOR filter is working:

- Insert all patterns into XOR filter  
- Skip patterns deemed “definitely absent”  
- Run Rabin–Karp only on remaining patterns  
- Benchmark improvements vs:  
  - Naive Rabin–Karp  
  - Rabin–Karp + Bloom Filter  
  - XOR-Filter-Enhanced Rabin–Karp  

---

## 🎯 Next Milestone
**Implement the XOR filter structure and build algorithm (peeling + reverse assignment).**

Once this is complete, Rabin–Karp integration becomes straightforward.

---

## 📘 Skills Learned So Far
- Implementing a robust 64-bit hash  
- Bit mixing and avalanche design  
- Correct handling of signed/unsigned types  
- Safe 64-bit output formatting  
- Hash derivation for probabilistic data structures  

---

## 📌 Future Enhancements (Optional)
- Add runtime benchmarks  
- Add unit tests  
- Support multiple fingerprint sizes  
- Add visualization of peeling steps  

