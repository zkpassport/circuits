// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {ZKPassportSubVerifier} from "./ZKPassportSubVerifier.sol";
import {ZKPassportHelper} from "./ZKPassportHelper.sol";
import {IRootRegistry, ProofVerificationParams} from "./Types.sol";

/**
 * @title   ZKPassport Root Verifier
 * @author  ZKPassport
 * @notice  Main entry point for verifying ZKPassport zero-knowledge proofs
 */
contract ZKPassportRootVerifier {
  address public admin;
  address public guardian;
  bool public paused;

  // ZKPassport Root Registry
  IRootRegistry public rootRegistry;

  // Subverifier mapping
  mapping(uint256 => ZKPassportSubVerifier) public subverifiers;

  // Helper mapping
  mapping(uint256 => ZKPassportHelper) public helpers;

  // Config mapping
  mapping(bytes32 key => bytes32 value) public config;

  // Events
  event RootVerifierDeployed(address admin, address guardian, address rootRegistry);
  event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
  event GuardianUpdated(address indexed oldGuardian, address indexed newGuardian);
  event RootRegistryUpdated(address indexed oldRootRegistry, address indexed newRootRegistry);
  event SubVerifierAdded(uint256 indexed version, address indexed subVerifier);
  event SubVerifierRemoved(uint256 indexed version, address indexed subVerifier);
  event SubVerifierUpdated(uint256 indexed version, address indexed oldSubVerifier, address indexed newSubVerifier);
  event HelperAdded(uint256 indexed version, address indexed helper);
  event HelperRemoved(uint256 indexed version, address indexed helper);
  event HelperUpdated(uint256 indexed version, address indexed oldHelper, address indexed newHelper);
  event PausedStatusChanged(bool paused);
  event ConfigUpdated(bytes32 indexed key, bytes32 oldValue, bytes32 newValue);

  /**
   * @notice Constructor
   * @param _admin The admin address
   * @param _guardian The guardian address
   * @param _rootRegistry The root registry address
   */
  constructor(address _admin, address _guardian, IRootRegistry _rootRegistry) {
    require(_admin != address(0), "Admin cannot be zero address");
    admin = _admin;
    guardian = _guardian;
    rootRegistry = _rootRegistry;
    emit RootVerifierDeployed(admin, guardian, address(_rootRegistry));
  }

  /**
   * @notice Verifies a ZKPassport zero-knowledge proof
   * @dev This function is called by the root verifier to verify a proof for a specific version
   * @param params The proof verification parameters
   * @return valid True if the proof is valid or false otherwise
   * @return uniqueIdentifier The unique identifier associated with the ID used to generate the proof
   * @return helper The helper for the calling contract to use to verify the committed inputs
   */
  function verify(
    ProofVerificationParams calldata params
  ) external view whenNotPaused returns (bool valid, bytes32 uniqueIdentifier, ZKPassportHelper helper) {
    ZKPassportSubVerifier subverifier = subverifiers[params.version];
    require(address(subverifier) != address(0), "Subverifier not found for version");
    (valid, uniqueIdentifier) = subverifier.verify(rootRegistry, params);
    return (valid, uniqueIdentifier, helpers[params.version]);
  }

  modifier onlyAdmin() {
    require(msg.sender == admin, "Not authorized: admin only");
    _;
  }

  modifier onlyAdminOrGuardian() {
    require(msg.sender == admin || msg.sender == guardian, "Not authorized: admin or guardian only");
    _;
  }

  modifier whenNotPaused() {
    require(!paused, "Root verifier is paused");
    _;
  }

  /**
   * @notice Transfers the admin role to a new address
   * @param newAdmin The new admin address
   */
  function transferAdmin(address newAdmin) external onlyAdmin {
    require(newAdmin != address(0), "Admin cannot be zero address");
    address oldAdmin = admin;
    admin = newAdmin;
    emit AdminUpdated(oldAdmin, newAdmin);
  }

  /**
   * @notice Sets the guardian role to a new address
   * @param newGuardian The new guardian address
   */
  function setGuardian(address newGuardian) external onlyAdmin {
    address oldGuardian = guardian;
    guardian = newGuardian;
    emit GuardianUpdated(oldGuardian, newGuardian);
  }

  /**
   * @notice Adds a subverifier for a specific version
   * @param version The version number
   * @param subVerifier The address of the subverifier
   */
  function addSubVerifier(uint256 version, ZKPassportSubVerifier subVerifier) external onlyAdmin {
    require(address(subVerifier) != address(0), "Subverifier cannot be zero address");
    require(version > 0, "Version must be greater than 0");
    require(address(subverifiers[version]) == address(0), "Subverifier already exists for version");
    subverifiers[version] = subVerifier;
    emit SubVerifierAdded(version, address(subVerifier));
  }

  /**
   * @notice Removes a subverifier for a specific version
   * @param version The version number
   */
  function removeSubVerifier(uint256 version) external onlyAdmin {
    require(version > 0, "Version must be greater than 0");
    require(version > 0, "Version must be greater than 0");
    address subVerifier = address(subverifiers[version]);
    require(subVerifier != address(0), "Subverifier not found for version");
    delete subverifiers[version];
    emit SubVerifierRemoved(version, subVerifier);
  }

  /**
   * @notice Updates a subverifier for a specific version
   * @param version The version number
   * @param newSubVerifier The address of the new subverifier
   */
  function updateSubVerifier(uint256 version, address newSubVerifier) external onlyAdmin {
    require(version > 0, "Version must be greater than 0");
    require(newSubVerifier != address(0), "Subverifier cannot be zero address");
    require(address(subverifiers[version]) != address(0), "Subverifier not found for version");
    address oldSubVerifier = address(subverifiers[version]);
    subverifiers[version] = ZKPassportSubVerifier(newSubVerifier);
    emit SubVerifierUpdated(version, oldSubVerifier, newSubVerifier);
  }

  /**
   * @notice Gets the subverifier address for a specific version
   * @dev Returns zero address if no subverifier exists for the given version
   * @param version The version number
   * @return The address of the subverifier contract, or zero address if not found
   */
  function getSubVerifier(uint256 version) external view returns (address) {
    return address(subverifiers[version]);
  }

  /**
   * @notice Adds a helper for a specific version
   * @param version The version number
   * @param newHelper The address of the helper
   */
  function addHelper(uint256 version, address newHelper) external onlyAdmin {
    require(newHelper != address(0), "Helper cannot be zero address");
    require(version > 0, "Version must be greater than 0");
    require(address(helpers[version]) == address(0), "Helper already exists for version");
    helpers[version] = ZKPassportHelper(newHelper);
    emit HelperAdded(version, newHelper);
  }

  /**
   * @notice Removes a helper for a specific version
   * @param version The version number
   */
  function removeHelper(uint256 version) external onlyAdmin {
    require(version > 0, "Version must be greater than 0");
    address helper = address(helpers[version]);
    require(helper != address(0), "Helper not found for version");
    delete helpers[version];
    emit HelperRemoved(version, helper);
  }

  /**
   * @notice Updates a helper for a specific version
   * @param version The version number
   * @param newHelper The address of the new helper
   */
  function updateHelper(uint256 version, address newHelper) external onlyAdmin {
    require(version > 0, "Version must be greater than 0");
    require(newHelper != address(0), "Helper cannot be zero address");
    require(address(helpers[version]) != address(0), "Helper not found for version");
    address oldHelper = address(helpers[version]);
    helpers[version] = ZKPassportHelper(newHelper);
    emit HelperUpdated(version, oldHelper, newHelper);
  }

  /**
   * @notice Gets the helper address for a specific version
   * @dev Returns zero address if no helper exists for the given version
   * @param version The version number
   * @return The address of the helper contract, or zero address if not found
   */
  function getHelper(uint256 version) external view returns (address) {
    return address(helpers[version]);
  }

  /**
    * @notice Update a config value
    * @param key The config key
    * @param value The config value
    */
  function updateConfig(bytes32 key, bytes32 value) external onlyAdmin {
    bytes32 oldValue = config[key];
    config[key] = value;
    emit ConfigUpdated(key, oldValue, value);
  }

  /**
    * @notice Pause the root verifier
    * @dev Only admin or guardian can pause the root verifier
    * @dev This is a security measure to pause all proof verification operations in the event of an emergency
    */
  function pause() external onlyAdminOrGuardian {
    paused = true;
    emit PausedStatusChanged(true);
  }

  /**
    * @notice Unpause the root verifier
    * @dev Only admin can unpause the root verifier
    */
  function unpause() external onlyAdmin {
    paused = false;
    emit PausedStatusChanged(false);
  }

}
