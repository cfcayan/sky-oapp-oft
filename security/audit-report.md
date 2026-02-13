# Security Audit Report (Bug Bounty Style)

## Scope
- Repository audited: `sky-oapp-oft`.
- Note: the requested URL `https://github.com/ethereum-optimism/op-geth` is **not** the code present in this checkout; this report is strictly for the local repository.
- Focus: Solidity contracts handling cross-chain governance and OFT bridging.

## Attack Surface Map

### Entrypoints and privileged actions
| Component | Entrypoint | Access control | Notes |
|---|---|---|---|
| Governance sender | `sendTx`, `quoteTx`, `setCanCallTarget` | public; `onlyOwner` for ACL changes | Arbitrary calldata/value can be routed cross-chain for allowlisted callers. |
| Governance receiver | `_lzReceive` (via LayerZero endpoint) | peer-gated by OApp | Decodes payload and performs external `call`. |
| OFT core | `setRateLimits`, `resetRateLimits`, `setRateLimitAccountingType`, `setPauser`, `pause`, `unpause` | owner/pauser | Throughput and emergency-stop controls. |
| OFT adapters | `withdrawFees`, `migrateLockedTokens` | `onlyOwner` | Treasury/funds movement functions. |

### Trust boundaries
- Cross-chain message payload (`_payload`) is untrusted data until validated and decoded safely.
- Owner-controlled configuration (allowlists, rate limits, migration) is high privilege.
- Token interactions (`innerToken`, mint/burn interfaces) are external-contract trust boundaries.

### External call sinks
- `dstTarget.call{value: msg.value}(dstCallData)` in governance receiver.
- `safeTransfer` / `safeTransferFrom` in adapters.
- `mint` / `burn` calls in mint-burn adapter.

### Parsing/deserialization
- Manual byte slicing in governance receiver (`_payload[0:32]`, `[44:64]`, `[64:]`).
- Packed message encoding in governance sender (`abi.encodePacked`).

### CI/CD and supply chain observations
- No `.github/workflows` files were found in this repository checkout during this review.

---

## Findings (sorted by severity)

## Medium

### F-01: Short governance payload can cause brittle decode failures (Input Validation / Availability)
**Location:** `contracts/GovernanceOAppReceiver.sol::_lzReceive` (payload slicing path).

#### Brief/Intro
The receiver decoded fixed offsets from cross-chain payload bytes without first checking minimum length. If malformed or truncated payloads are delivered, execution reverts at decode time, causing governance message failures and reducing cross-chain governance reliability.

#### Vulnerability Details
`_lzReceive` uses direct slices:
- `_payload[0:32]` for `srcSender`
- `_payload[44:64]` for destination address
- `_payload[64:]` for calldata

Without a length guard, payloads `<64` bytes cause decode-time revert. Even with trusted peers, malformed packets can occur due to config drift, version mismatch, or integration bugs and should fail with explicit validation errors.

**Implemented safe fix in this branch:**
```solidity
if (_payload.length < 64) revert InvalidPayloadLength(_payload.length);
```
And custom error:
```solidity
error InvalidPayloadLength(uint256 payloadLength);
```

#### Impact Details
- Governance actions can fail repeatedly when malformed packets are submitted.
- Operational impact: delayed execution of time-sensitive governance operations.
- Availability impact is primary; no direct private-key theft path observed from this issue alone.

#### Safe Reproduction (local)
1. In local Foundry tests, call the endpoint `lzReceive` with a payload shorter than 64 bytes.
2. Observe revert with `InvalidPayloadLength`.

#### Fix
- Keep explicit schema validation before any fixed-offset slicing.
- Consider adding a message version byte and canonical decoder for forward compatibility.

#### Patch
- `contracts/GovernanceOAppReceiver.sol`
- `contracts/interfaces/IGovernanceOAppReceiver.sol`
- `test/foundry/Governance.t.sol` (new regression test)

#### Verification
- Confirm malformed payload test reverts with `InvalidPayloadLength`.
- Confirm existing happy-path governance tests still pass.

#### References
- LayerZero OApp receiver pattern docs: https://docs.layerzero.network/
- Solidity calldata slicing behavior: https://docs.soliditylang.org/

---

## Low

### F-02: Zero-address/no-code governance targets are allowed (Insecure Configuration)
**Location:** `contracts/GovernanceOAppSender.sol::setCanCallTarget/sendTx`, `test/foundry/Governance.t.sol::test_governed_contract_can_be_zero_address`.

- **Why vulnerable:** Allowlisting zero/no-code targets can cause silent no-op governance “success” or accidental value loss.
- **Reachability:** Owner configuration plus allowlisted caller invoking `sendTx`.
- **Impact:** Misrouted governance, potential native value loss.
- **Fix:** enforce non-zero target and optional `code.length > 0` unless explicit value-only mode is enabled.

### F-03: Fee withdrawal lacks explicit zero-address recipient guard (Misconfiguration)
**Location:** `contracts/SkyOFTAdapter.sol::withdrawFees`, `contracts/SkyOFTAdapterMintBurn.sol::withdrawFees`.

- **Why vulnerable:** Operator can accidentally burn fees by sending to `address(0)`.
- **Impact:** Irrecoverable treasury loss.
- **Fix:** add `_to != address(0)` guard.

### F-04: High concentration of power in owner key (Privileged Access)
**Location:** owner-only controls across governance/OFT contracts.

- **Why vulnerable:** One compromised key can alter ACLs, limits, pauses, and migration behavior.
- **Impact:** Protocol-wide control loss.
- **Fix:** multisig + timelock + role splitting.

---

## Top 10 Risks (priority order)
1. Malformed governance payload handling can degrade governance availability.
2. Zero/no-code target configuration can cause misexecution and value loss.
3. Single owner key controls multiple critical paths.
4. Locked token migration is highly sensitive and should be timelocked.
5. Fee withdrawal misconfiguration can burn treasury assets.
6. Manual packed payload parsing is brittle for future upgrades.
7. Dependence on downstream origin-check discipline can be misconfigured.
8. Governance value forwarding can cause unintended native-asset transfer patterns.
9. Rate limit misconfiguration can halt bridging or weaken protections.
10. Limited visible CI security automation in this checkout.

## Hardening Recommendations
- Keep strict payload length/version validation and centralized decode helpers.
- Add target validation policy (non-zero + code checks by default).
- Adopt multisig+timelock for owner paths; split emergency and treasury roles.
- Add fuzz/property tests for payload decoding and origin propagation.
- Integrate static analysis (Slither) and security checks into CI.
