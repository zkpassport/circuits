// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity ^0.8.30;
import {ZKPassportRootVerifier as RootVerifier} from "./ZKPassportRootVerifier.sol";
import {IRootRegistry} from "./IRootRegistry.sol";
import {IProofVerifier} from "../src/IProofVerifier.sol";
import {ProofVerificationParams, NullifierType, ProofVerifier} from "./Types.sol";
import {PublicInput, RegistryID} from "./Constants.sol";
import {DateUtils} from "./DateUtils.sol";
import {StringUtils} from "./StringUtils.sol";

contract ZKPassportSubVerifier {
  address public admin;
  bool public paused;

  // The address of the root verifier
  RootVerifier public rootVerifier;

  // Mapping from vkey hash of each outer circuit to its proof verifier (UltraHonk verifier) address
  mapping(bytes32 => address) public proofVerifiers;

  // Events
  event ZKPassportSubVerifierDeployed(address indexed admin, address indexed rootVerifier);
  event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
  event ProofVerifierAdded(address indexed proofVerifier, bytes32 indexed vkeyHash);
  event ProofVerifierRemoved(address indexed proofVerifier, bytes32 indexed vkeyHash);
  event PausedStatusChanged(bool paused);

  /**
   * @dev Constructor
   * @param _admin The admin address
   * @param _rootVerifier The address of the ZKPassport root verifier
   */
  constructor(address _admin, RootVerifier _rootVerifier) {
    require(_admin != address(0), "Admin cannot be zero address");
    admin = _admin;
    require(address(_rootVerifier) != address(0), "Root verifier cannot be zero address");
    rootVerifier = _rootVerifier;
    emit ZKPassportSubVerifierDeployed(admin, address(_rootVerifier));
  }

  modifier onlyAdmin() {
    require(msg.sender == admin, "Not authorized: admin only");
    _;
  }

  modifier onlyRootVerifier() {
    require(msg.sender == address(rootVerifier), "This function can only be called from the root verifier");
    _;
  }

  modifier whenNotPaused() {
    require(!paused, "Contract is paused");
    _;
  }

  function transferAdmin(address newAdmin) external onlyAdmin {
    require(newAdmin != address(0), "Admin cannot be zero address");
    address oldAdmin = admin;
    admin = newAdmin;
    emit AdminUpdated(oldAdmin, newAdmin);
  }

  function setPaused(bool _paused) external onlyAdmin {
    paused = _paused;
    emit PausedStatusChanged(_paused);
  }

  function addProofVerifiers(ProofVerifier[] calldata _proofVerifiers) external onlyAdmin {
    for (uint256 i = 0; i < _proofVerifiers.length; i++) {
      proofVerifiers[_proofVerifiers[i].vkeyHash] = _proofVerifiers[i].verifier;
      emit ProofVerifierAdded(_proofVerifiers[i].verifier, _proofVerifiers[i].vkeyHash);
    }
  }

  function removeProofVerifiers(bytes32[] calldata vkeyHashes) external onlyAdmin {
    for (uint256 i = 0; i < vkeyHashes.length; i++) {
      address proofVerifier = proofVerifiers[vkeyHashes[i]];
      if (proofVerifier != address(0)) {
        delete proofVerifiers[vkeyHashes[i]];
        emit ProofVerifierRemoved(proofVerifier, vkeyHashes[i]);
      }
    }
  }

  function _checkDateValidity(uint256 currentDateTimeStamp, uint256 validityPeriodInSeconds)
    internal
    view
    returns (bool)
  {
    return DateUtils.isDateValid(currentDateTimeStamp, validityPeriodInSeconds);
  }

  /**
   * @notice Verifies that the proof was generated for the given scope (domain) and subscope (service scope)
   * @param publicInputs The public inputs of the proof
   * @param scope The scope (domain) to check against
   * @param subscope The subscope (service scope) to check against
   * @return True if valid, false otherwise
   */
  function _verifyScopes(bytes32[] calldata publicInputs, string calldata scope, string calldata subscope)
    internal
    pure
    returns (bool)
  {
    // One byte is dropped at the end
    // What we call scope internally is derived from the domain
    bytes32 scopeHash = StringUtils.isEmpty(scope) ? bytes32(0) : sha256(abi.encodePacked(scope)) >> 8;
    // What we call the subscope internally is the service scope specified manually in the SDK
    bytes32 subscopeHash = StringUtils.isEmpty(subscope) ? bytes32(0) : sha256(abi.encodePacked(subscope)) >> 8;
    return
      publicInputs[PublicInput.SCOPE_INDEX] == scopeHash && publicInputs[PublicInput.SUBSCOPE_INDEX] == subscopeHash;
  }

  function _verifyCommittedInputs(bytes32[] memory paramCommitments, bytes calldata committedInputs) internal pure {
    uint256 offset = 0;
    uint256 index = 0;
    while (offset < committedInputs.length && index < paramCommitments.length) {
      // The committed inputs are formatted as follows:
      // - 1 byte: proof type
      // - 2 bytes: length of the committed inputs
      // - N bytes: committed inputs for a given proof
      uint16 length = uint16(bytes2(committedInputs[offset + 1:offset + 3]));
      // One byte is dropped inside the circuit as BN254 is limited to 254 bits
      // We also add 3 bytes to take into account the proof type and length
      bytes32 calculatedCommitment = sha256(abi.encodePacked(committedInputs[offset:offset + length + 3])) >> 8;
      require(calculatedCommitment == paramCommitments[index], "Invalid commitment");
      offset += length + 3;
      index++;
    }
    // Check that all the committed inputs have been covered, otherwise something is wrong
    require(offset == committedInputs.length, "Invalid committed inputs length");
    require(index == paramCommitments.length, "Invalid parameter commitments");
  }

  function _getProofVerifier(bytes32 vkeyHash) internal view returns (address) {
    address verifier = proofVerifiers[vkeyHash];
    require(verifier != address(0), "Verifier not found");
    return verifier;
  }

  function _validateCertificateRoot(IRootRegistry _rootRegistry, bytes32 certificateRoot, uint256 timestamp)
    internal
    view
  {
    require(
      _rootRegistry.isRootValid(RegistryID.CERTIFICATE, certificateRoot, timestamp),
      "Invalid certificate registry root"
    );
  }

  function _validateCircuitRoot(IRootRegistry _rootRegistry, bytes32 circuitRoot, uint256 timestamp) internal view {
    require(_rootRegistry.isRootValid(RegistryID.CIRCUIT, circuitRoot, timestamp), "Invalid circuit registry root");
  }

  /**
   * @notice Verifies a ZKPassport proof
   * @dev This function is called by the root verifier to verify a proof for a specific version
   * @param rootRegistry The root registry
   * @param params The proof verification parameters
   * @return isValid True if the proof is valid, false otherwise
   * @return uniqueIdentifier The unique identifier associated to the identity document that generated the proof
   */
  function verify(IRootRegistry rootRegistry, ProofVerificationParams calldata params)
    external
    view
    whenNotPaused
    onlyRootVerifier
    returns (bool isValid, bytes32 uniqueIdentifier)
  {
    // Get the verifier for the Outer Circuit corresponding to the vkey hash
    address verifier = _getProofVerifier(params.proofVerificationData.vkeyHash);

    uint256 currentTimestamp = uint256(params.proofVerificationData.publicInputs[PublicInput.CURRENT_DATE_INDEX]);

    // Validate certificate registry root
    _validateCertificateRoot(
      rootRegistry,
      params.proofVerificationData.publicInputs[PublicInput.CERTIFICATE_REGISTRY_ROOT_INDEX],
      currentTimestamp
    );

    // Validate circuit registry root
    _validateCircuitRoot(
      rootRegistry, params.proofVerificationData.publicInputs[PublicInput.CIRCUIT_REGISTRY_ROOT_INDEX], currentTimestamp
    );

    // Checks the date of the proof
    // This is the current date used as public input in the disclosure proofs
    // so verifying it here guarantees that the disclosure proofs were generated with this date
    require(
      _checkDateValidity(currentTimestamp, params.serviceConfig.validityPeriodInSeconds),
      "The proof was generated outside the validity period"
    );

    // Validate scopes
    // It is recommended to verify this against static variables in your contract
    // by calling `helper.verifyScopes(publicInputs, domain, scope)` or setting the domain and scope
    // in the params inside your smart contract function before calling `verifier.verify(params)`
    // Check SampleContract.sol for an example
    require(
      _verifyScopes(params.proofVerificationData.publicInputs, params.serviceConfig.domain, params.serviceConfig.scope),
      "Invalid domain or scope"
    );

    // Verifies the commitments against the committed inputs
    _verifyCommittedInputs(
      // Extracts the commitments from the public inputs
      params.proofVerificationData
      .publicInputs[PublicInput.PARAM_COMMITMENTS_INDEX:params.proofVerificationData.publicInputs.length - 2],
      params.committedInputs
    );

    NullifierType nullifierType = NullifierType(
      uint256(params.proofVerificationData.publicInputs[params.proofVerificationData.publicInputs.length - 2])
    );

    // Allow mock proofs in dev mode
    // Note: On mainnets, this stage won't be reached as the ZKR certificates will not be part
    // of the mainnet registries and the verification will fail at _validateCertificateRoot
    require(
      (nullifierType != NullifierType.NON_SALTED_MOCK_NULLIFIER && nullifierType != NullifierType.SALTED_MOCK_NULLIFIER)
        || params.serviceConfig.devMode,
      "Mock proofs are only allowed in dev mode"
    );

    // For now, only non-salted nullifiers are supported
    // but salted nullifiers can be used in dev mode
    // They will be later once a proper registration mechanism is implemented
    require(
      nullifierType == NullifierType.NON_SALTED_NULLIFIER || params.serviceConfig.devMode,
      "Salted nullifiers are not supported for now"
    );

    // Call the proof verifier for the given Outer Circuit to verify if the actual proof is valid
    isValid =
      IProofVerifier(verifier).verify(params.proofVerificationData.proof, params.proofVerificationData.publicInputs);

    // Get the unique identifier from the public inputs
    uint256 uniqueIdentifierIndex = params.proofVerificationData.publicInputs.length - 1;
    uniqueIdentifier = params.proofVerificationData.publicInputs[uniqueIdentifierIndex];

    // Return the validity of the proof verification and the unique identifier
    return (isValid, uniqueIdentifier);
  }
}
