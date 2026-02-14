# Security Audit Report (Bug Bounty Style)

## Scope
- Repository audited: `sky-oapp-oft` (local checkout only).
- Requested upstream URL (`op-geth`) is not this repository; no external systems were touched.
- Focus area for this revision: `GovernanceOAppSender`.

## Attack Surface Map

### GovernanceOAppSender attack surface
| Surface | Code Location | Trust Boundary | Notes |
|---|---|---|---|
| Target allowlisting | `setCanCallTarget(address,uint32,bytes32,bool)` | Owner input | No destination sanity checks (e.g., zero target). |
| Cross-chain dispatch | `sendTx(TxParams,MessagingFee,address)` | Allowlisted caller input | Sends user-controlled target+calldata to remote receiver if allowlisted. |
| Message construction | `_buildMsgAndOptions(TxParams)` | Caller input serialization | `abi.encodePacked(msg.sender,dstTarget,dstCallData)` fixed-header packed format. |

---

## Finding: GovernanceOAppSender permits unsafe zero-address target configuration
**Severity:** Medium  
**Category:** Insecure Design / Misconfiguration leading to loss of funds and governance misexecution  
**Location:** `contracts/GovernanceOAppSender.sol` (`setCanCallTarget`, `sendTx`) and downstream execution in `contracts/GovernanceOAppReceiver.sol`.

### Brief/Intro
`GovernanceOAppSender` allows owner to approve `dstTarget = bytes32(0)` and allows allowlisted callers to send governance messages to that target, which can result in governance operations that appear successful but execute no contract logic; if native value is forwarded, this can permanently misroute/burn value in production.

### Vulnerability Details
The sender ACL path has no target validation:

```solidity
function setCanCallTarget(address _srcSender, uint32 _dstEid, bytes32 _dstTarget, bool _canCall) external onlyOwner {
    if (canCallTarget[_srcSender][_dstEid][_dstTarget] == _canCall) revert CanCallTargetIdempotent();
    canCallTarget[_srcSender][_dstEid][_dstTarget] = _canCall;
}
```

And dispatch only checks ACL membership:

```solidity
if (!canCallTarget[msg.sender][_params.dstEid][_params.dstTarget]) revert CannotCallTarget();
msgReceipt = _lzSend(_params.dstEid, message, options, _fee, _refundAddress);
```

Because `_params.dstTarget` is not rejected when zero/no-code, the remote receiver still attempts:

```solidity
(bool success, bytes memory returnData) = dstTarget.call{ value: msg.value }(dstCallData);
```

For zero-address/no-code targets, this call may return success without executing intended governance logic. This is a real vulnerability because it creates a high-probability operator/misconfiguration failure mode in a privileged governance channel (already reflected by local test coverage permitting zero target behavior).

### Impact Details
Potential in-scope impacts:
- **Governance integrity loss:** critical actions (parameter updates, role changes, emergency calls) can be “sent” but not actually executed on intended destination contracts.
- **Fund loss risk:** when messages carry native value, funds can be sent to an unintended non-contract/zero target path and become unrecoverable.
- **Operational and incident-response cost:** false-positive execution status can delay detection and remediation during urgent governance events.

Practical consequence on mainnet is governance desynchronization across chains and possible permanent treasury/native token loss for value-bearing messages.

### Proof of Concept (local-only)
1. Use local Foundry setup from `test/foundry/Governance.t.sol`.
2. Owner allowlists zero target:
   - `aGov.setCanCallTarget(address(this), bEid, addressToBytes32(address(0)), true);`
3. Caller sends tx with `dstTarget = addressToBytes32(address(0))` and empty calldata.
4. Packet verifies/executed; no intended governed contract logic runs.
5. On vulnerable revisions, this flow succeeds; in this patched revision, it is blocked by `InvalidGovernanceTarget` and covered by regression tests.

### Recommended Fix
- Reject zero target in sender ACL and dispatch paths.
- Optionally enforce `code.length > 0` on destination target in receiver (or via a strict allowlist policy).
- If value-only transfers are a product requirement, add an explicit dedicated mode/flag so it cannot be confused with governance call execution.

Minimal safe patch pattern (sender-side):
```solidity
if (_dstTarget == bytes32(0)) revert InvalidGovernanceTarget();
```
(and analogous check in `sendTx` for defense in depth).

### Verification
- Add unit tests asserting:
  - `setCanCallTarget(..., bytes32(0), true)` reverts.
  - `sendTx` with `_params.dstTarget == bytes32(0)` reverts.
  - Normal non-zero, valid contract targets still work.

### References
- Local code: `contracts/GovernanceOAppSender.sol`
- Local code: `contracts/GovernanceOAppReceiver.sol`
- Local regression tests in patched version: `test/foundry/Governance.t.sol::test_governed_contract_cannot_be_zero_address`, `test_send_reverts_with_zero_target`
- LayerZero docs: https://docs.layerzero.network/
- Solidity call semantics: https://docs.soliditylang.org/en/latest/control-structures.html#external-function-calls

---

## Top 10 Risks (quick priority)
1. Unsafe target acceptance in governance sender (`bytes32(0)` / non-code target).
2. Governance message payload parsing brittleness across upgrades.
3. Single-key owner concentration over ACL/rate-limit/pause controls.
4. Sensitive locked-token migration authority on owner.
5. Fee-withdrawal operator mistakes (zero-address burn risk) in adapters.
6. Value-forwarding governance calls increase blast radius of misconfiguration.
7. Dependency on downstream receiver-side validation discipline.
8. Cross-chain configuration drift (peer/target mismatch) causing governance outages.
9. Rate-limit misconfiguration causing transfer DoS or weakened controls.
10. Limited visible CI security automation in current checkout.
