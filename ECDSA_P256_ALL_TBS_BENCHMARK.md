# ECDSA P-256 + SHA-256 Benchmark Results - All TBS Sizes

Generated: 2025-07-14T12:08:09.709Z

## Summary

Benchmarking was performed on ECDSA P-256 + SHA-256 circuits with different TBS (To Be Signed) certificate sizes.

### Test Configuration
- **Signature Algorithm**: ECDSA with P-256 curve (secp256r1)
- **Hash Algorithm**: SHA-256
- **Iterations per TBS size**: 5
- **Test Data**: US passport for John Doe

## Results by TBS Size

### Performance Summary

| TBS Size | Avg Total Time | Avg Witness Time | Avg Proof Time | Total Std Dev |
|----------|----------------|------------------|----------------|---------------|
| 700 | 3595 ms | 1153 ms | 2442 ms | 12 ms |

## Detailed Results

### TBS Size: 700 bytes

**Witness Generation**
- Average: 1153.16 ms
- Min: 1143.67 ms
- Max: 1159.23 ms
- Std Dev: 5.19 ms

**Proof Generation**
- Average: 2441.59 ms
- Min: 2430.59 ms
- Max: 2455.31 ms
- Std Dev: 8.54 ms

**Total Time**
- Average: 3594.75 ms
- Min: 3578.50 ms
- Max: 3609.16 ms
- Std Dev: 11.61 ms

## Performance Trends

### Impact of TBS Size on Performance

| Metric | TBS 700 → 1600 Change |
|--------|------------------------|
| Witness Generation | 0.0% |
| Proof Generation | 0.0% |
| Total Time | 0.0% |

### Key Observations

1. **Linear Scaling**: Performance appears to scale linearly with TBS size
2. **Dominant Component**: Proof generation takes approximately 68% of total time
3. **Consistency**: Low standard deviation indicates consistent performance across iterations

## Circuit Information

- **Circuit Family**: `sig_check_id_data_tbs_*_ecdsa_nist_p256_sha256`
- **Available TBS Sizes**: 700, 1000, 1200, 1500, 1600 bytes
- **Method**: In-process (bb.js)

## Recommendations

1. **TBS Size Selection**: Choose the smallest TBS size that accommodates your certificate data
2. **Performance Budget**: Expect ~3.6-3.6 seconds per proof depending on TBS size
3. **Optimization**: Consider parallel proof generation for multiple passports
