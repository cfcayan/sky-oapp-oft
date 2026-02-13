# Security Audit Report (Bug Bounty Style)

## Scope
- Repository audited: `sky-oapp-oft`
- Requested upstream reference: `op-geth` (not present in this repository checkout)
- Review focus: Solidity contracts, cross-chain governance/OFT paths, config/build/test scripts.

## Attack Surface Map

### 1) Entrypoints / privileged operations

| Component | Entrypoint | Access control | Security relevance |
|---|---|---|---|
| Governance sender | `sendTx`, `quoteTx`, `setCanCallTarget` | Public + `onlyOwner` for ACL management | Sends arbitrary calldata/value to remote receiver if sender is allowlisted. |
| Governance receiver | `_lzReceive` | LayerZero peer-gated by inherited OApp checks | Decodes payload, sets global `messageOrigin`, executes external call. |
| OFT adapter (lock/unlock) | `withdrawFees`, `migrateLockedTokens`, OFT send/receive internals | `onlyOwner` for admin ops | Holds user funds/fees and can migrate locked assets. |
| OFT adapter (mint/burn) | `withdrawFees`, OFT send/receive internals | `onlyOwner` for admin fee ops | Mints/burns token via privileged token hooks. |
| OFT core controls | `setRateLimits`, `resetRateLimits`, `setRateLimitAccountingType`, `setPauser`, `pause`, `unpause` | Owner / pauser roles | Directly controls transfer availability and throughput. |

### 2) Trust boundaries
- Cross-chain payloads are untrusted at protocol boundary and become trusted only after peer validation. Payload parsing still needs defensive validation. 
- `sendTx` user input: destination endpoint, target, calldata, extra options are attacker-controlled for any allowlisted caller.
- Token contracts (`innerToken`) are external dependencies and may have non-standard behavior.
- Owner key is a high-trust boundary controlling allowlists, pausing, rate-limits, and fund migration.

### 3) External calls / execution sinks
- Arbitrary `call` to decoded target in governance receiver (`dstTarget.call{value: msg.value}(dstCallData)`).
- ERC20 token transfers and transferFrom in adapters.
- Mint/burn external interface calls in mint/burn adapter.

### 4) Parsing / deserialization
- Manual byte slicing in governance receiver (`_payload[0:32]`, `[44:64]`, `[64:]`).
- Packed encoding in sender (`abi.encodePacked(msgSenderBytes32, dstTarget, dstCallData)`).

### 5) File handling / command execution / background jobs / CI-CD
- No direct file upload/path traversal surfaces in on-chain contracts.
- No shell command execution in audited contracts.
- No GitHub Actions workflows found in this checkout during this review.

## Findings

### Medium — Defensive parsing gap in governance message decoding (DoS by malformed packet)
- **Category:** Input Validation / Availability
- **Location:** `contracts/GovernanceOAppReceiver.sol`, `_lzReceive`, around payload slicing logic.
- **Why vulnerable:** The function slices fixed ranges from `_payload`; malformed short payloads can revert unexpectedly and force failed message processing paths. Even if sender peer is trusted, malformed packets from misconfiguration/upgrades can create availability incidents.
- **Reachability:** Local LayerZero test path that invokes receiver `lzReceive` with truncated payload.
- **Impact:** Message execution failures and operational recovery burden; depending on transport semantics, can delay subsequent governance operations.
- **Safe reproduction:** In local tests, call receive path with payload length `< 64` and observe deterministic revert.
- **Fix:** Add explicit minimum payload length check with custom error before slicing.
- **Patch:** Implemented in this branch.
- **Verification:** Add/execute test asserting custom revert on short payload and successful execution on valid payload.

### Medium — Governance call target can be zero-address/no-code target (unsafe configuration pattern)
- **Category:** Insecure Design / Access Control Hardening
- **Location:** `contracts/GovernanceOAppSender.sol` (`setCanCallTarget`/`sendTx`), `contracts/GovernanceOAppReceiver.sol` (`dstTarget.call`), behavior validated by `test/foundry/Governance.t.sol::test_governed_contract_can_be_zero_address`.
- **Why vulnerable:** Current design allows allowlisting `bytes32(0)` and dispatching governance calls to non-contract targets. This increases operator error risk (silent no-op success, accidental value burns/transfers, hard-to-detect misroutes).
- **Reachability:** Any owner-managed allowlist entry can permit this pattern.
- **Impact:** Governance operations may appear successful while not executing intended code; funds sent as value can be lost/misdirected.
- **Safe reproduction:** Local test already demonstrates zero-address target acceptance.
- **Fix:** Enforce `dstTarget != 0` and optionally `code.length > 0` unless an explicit “value-only transfer” mode is enabled.
- **Patch:** Recommended (not applied here to avoid behavior-breaking change).
- **Verification:** New tests should fail for zero-address / no-code target unless explicit flag is set.

### Low — Fee withdrawal allows zero-address recipient in adapters
- **Category:** Misconfiguration / Funds Safety
- **Location:** `contracts/SkyOFTAdapter.sol::withdrawFees`, `contracts/SkyOFTAdapterMintBurn.sol::withdrawFees`.
- **Why vulnerable:** Missing `_to != address(0)` guard can irreversibly burn fee assets on admin error.
- **Reachability:** Owner-only function, but operational mistakes remain realistic.
- **Impact:** Irrecoverable fee loss.
- **Safe reproduction:** Local unit test with owner withdrawing to zero address.
- **Fix:** Reuse `InvalidAddressZero` style checks before transfer.
- **Patch:** Recommended.
- **Verification:** Ensure zero-address call reverts, non-zero still succeeds.

### Low — Single-key concentration for high-impact controls
- **Category:** Privileged Access / Governance Hardening
- **Location:** Owner-gated controls across `SkyOFTCore`, `SkyOFTAdapter`, `GovernanceOAppSender`.
- **Why vulnerable:** A compromised owner can pause/unpause, rewrite allowlists, alter rate limits, and migrate locked tokens.
- **Reachability:** Owner key compromise or misuse.
- **Impact:** Full protocol control and potential fund flow disruption.
- **Safe reproduction:** Local test with owner role demonstrates broad control.
- **Fix:** Use multisig + timelock + role separation (ops vs emergency pause vs treasury migration).
- **Patch:** Architectural recommendation.
- **Verification:** Governance playbook tests for delayed execution and role-scoped permissions.

## Top 10 Risks (priority order)
1. Malformed governance payload handling can degrade cross-chain governance availability.
2. Zero/no-code governance targets create high operator-error blast radius.
3. Single owner key controls multiple critical security functions.
4. Owner-triggered locked-token migration is highly sensitive and should be timelocked.
5. Fee withdrawal to zero address can burn recoverable treasury value.
6. Manual packed payload decoding is brittle across future protocol changes.
7. Dependence on downstream governed-contract origin checks is easy to misconfigure.
8. Value forwarding in governance calls can produce unexpected native-asset movements.
9. Rate-limit misconfiguration can halt bridging or weaken congestion protection.
10. Limited CI/security automation visibility in current checkout (no workflow evidence observed).

## Hardening Recommendations
- Enforce strict payload schema checks + version byte in governance message format.
- Add target validation policy (non-zero, code check, optional explicit value-only mode).
- Move owner to multisig + timelock; split roles for pause, config, treasury migration.
- Add invariant tests for governance relay origin verification and failure handling.
- Add static-analysis and fuzzing in CI (Slither, Echidna/Foundry fuzz, semgrep for scripts).
