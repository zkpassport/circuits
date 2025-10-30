// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {IZKPassportVerifier, ProofVerificationParams} from "./Types.sol";

contract ZKPassportRootVerifier {
  address public admin;
  address public guardian;
  bool public paused;

  mapping(uint256 => IZKPassportVerifier) public verifiers;

  // Events
  event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
  event GuardianUpdated(address indexed oldGuardian, address indexed newGuardian);
  event VerifierAdded(uint256 indexed version, address indexed verifier);
  event VerifierRemoved(uint256 indexed version, address indexed verifier);
  event VerifierUpdated(uint256 indexed version, address indexed oldVerifier, address indexed newVerifier);
  event PausedStatusChanged(bool paused);

  /**
   * @dev Constructor
   * @param _admin The address of the admin
   * @param _guardian The address of the guardian
   * @param _version The initial version number for the verifier
   * @param _verifier The address of the ZKPassport verifier implementation
   */
  constructor(address _admin, address _guardian, uint256 _version, address _verifier) {
    require(_admin != address(0), "Admin cannot be zero address");
    require(_verifier != address(0), "Verifier cannot be zero address");
    require(_version > 0, "Version must be greater than 0");
    admin = _admin;
    guardian = _guardian;
    verifiers[_version] = IZKPassportVerifier(_verifier);
    emit VerifierAdded(_version, _verifier);
  }

  /**
   * @notice Verifies a ZKPassport proof using a specific verifier version
   * @param version The version number of the verifier to use
   * @param params The proof verification parameters
   * @return valid True if the proof is valid or false otherwise
   * @return uniqueIdentifier The unique identifier associated with the ID used to generate the proof
   */
  function verify(
    uint256 version,
    ProofVerificationParams calldata params
  ) external view whenNotPaused returns (bool valid, bytes32 uniqueIdentifier) {
    IZKPassportVerifier verifier = verifiers[version];
    require(address(verifier) != address(0), "Verifier not found for version");
    (valid, uniqueIdentifier) = verifier.verifyProof(params);
    return (valid, uniqueIdentifier);
  }

  modifier onlyAdmin() {
    require(msg.sender == admin, "Not authorized: admin only");
    _;
  }

  modifier onlyGuardian() {
    require(msg.sender == guardian, "Not authorized: guardian only");
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

  function setGuardian(address newGuardian) external onlyAdmin {
    address oldGuardian = guardian;
    guardian = newGuardian;
    emit GuardianUpdated(oldGuardian, newGuardian);
  }

  /**
   * @notice Gets the verifier address for a specific version
   * @param version The version number
   * @return The verifier address for the given version
   */
  function getVerifier(uint256 version) external view returns (address) {
    return address(verifiers[version]);
  }

  /**
   * @notice Adds a verifier for a specific version
   * @param version The version number
   * @param newVerifier The address of the verifier
   */
  function addVerifier(uint256 version, address newVerifier) external onlyAdmin {
    require(newVerifier != address(0), "Verifier cannot be zero address");
    require(version > 0, "Version must be greater than 0");
    require((address)(verifiers[version]) == address(0), "Verifier already exists for version");
    verifiers[version] = IZKPassportVerifier(newVerifier);
    emit VerifierAdded(version, newVerifier);
  }

  /**
   * @notice Removes a verifier for a specific version
   * @param version The version number
   */
  function removeVerifier(uint256 version) external onlyAdmin {
    require(version > 0, "Version must be greater than 0");
    address verifierAddress = address(verifiers[version]);
    require(verifierAddress != address(0), "Verifier not found for version");
    delete verifiers[version];
    emit VerifierRemoved(version, verifierAddress);
  }

  /**
   * @notice Updates a verifier for a specific version
   * @param version The version number
   * @param newVerifier The address of the verifier
   */
  function updateVerifier(uint256 version, address newVerifier) external onlyAdmin {
    require(version > 0, "Version must be greater than 0");
    require(newVerifier != address(0), "Verifier cannot be zero address");
    require((address)(verifiers[version]) != address(0), "Verifier not found for version");
    address oldVerifier = address(verifiers[version]);
    verifiers[version] = IZKPassportVerifier(newVerifier);
    emit VerifierUpdated(version, oldVerifier, newVerifier);
  }

  function setPaused(bool _paused) external onlyGuardian {
    paused = _paused;
    emit PausedStatusChanged(_paused);
  }
}
