// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {ZKPassportSubVerifier} from "./ZKPassportSubVerifier.sol";
import {ZKPassportHelper} from "./ZKPassportHelper.sol";
import {IRootRegistry, ProofVerificationParams} from "./Types.sol";

contract ZKPassportRootVerifier {
  address public admin;
  address public guardian;
  bool public paused;
  IRootRegistry public rootRegistry;
  mapping(uint256 => ZKPassportSubVerifier) public subverifiers;
  mapping(uint256 => ZKPassportHelper) public helpers;
  mapping(bytes32 => bytes32) public configs;

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

  /**
   * @dev Constructor
   * @param _admin The address of the admin
   * @param _guardian The address of the guardian
   * @param _rootRegistry The address of the root registry
   */
  constructor(address _admin, address _guardian, IRootRegistry _rootRegistry) {
    require(_admin != address(0), "Admin cannot be zero address");
    admin = _admin;
    guardian = _guardian;
    rootRegistry = _rootRegistry;
    emit RootVerifierDeployed(admin, guardian, address(_rootRegistry));
  }

  /**
   * @notice Verifies a ZKPassport proof using a specific verifier version
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

  modifier onlyGuardian() {
    require(msg.sender == guardian, "Not authorized: guardian only");
    _;
  }

  modifier whenNotPaused() {
    require(!paused, "Contract is paused");
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
   * @notice Gets the sub verifier address for a specific version
   * @param version The version number
   * @return The address of the sub verifier
   */
  function getSubVerifier(uint256 version) external view returns (address) {
    return address(subverifiers[version]);
  }

  /**
   * @notice Adds a sub verifier for a specific version
   * @param version The version number
   * @param subVerifier The address of the sub verifier
   */
  function addSubVerifier(uint256 version, ZKPassportSubVerifier subVerifier) external onlyAdmin {
    require(address(subVerifier) != address(0), "Sub verifier cannot be zero address");
    require(version > 0, "Version must be greater than 0");
    require((address)(subverifiers[version]) == address(0), "Sub verifier already exists for version");
    subverifiers[version] = subVerifier;
    emit SubVerifierAdded(version, address(subVerifier));
  }

  /**
   * @notice Removes a specific version of a sub verifier
   * @param version The version number
   */
  function removeSubVerifier(uint256 version) external onlyAdmin {
    require(version > 0, "Version must be greater than 0");
    address subVerifier = address(subverifiers[version]);
    require(subVerifier != address(0), "Sub verifier not found for version");
    delete subverifiers[version];
    emit SubVerifierRemoved(version, subVerifier);
  }

  /**
   * @notice Updates a specific version of a sub verifier
   * @param version The version number
   * @param newSubVerifier The address of the new sub verifier
   */
  function updateSubVerifier(uint256 version, address newSubVerifier) external onlyAdmin {
    require(version > 0, "Version must be greater than 0");
    require(newSubVerifier != address(0), "Sub verifier cannot be zero address");
    require((address)(subverifiers[version]) != address(0), "Sub verifier not found for version");
    address oldSubVerifier = address(subverifiers[version]);
    subverifiers[version] = ZKPassportSubVerifier(newSubVerifier);
    emit SubVerifierUpdated(version, oldSubVerifier, newSubVerifier);
  }

  /**
   * @notice Adds a helper for a specific version
   * @param version The version number
   * @param newHelper The address of the helper
   */
  function addHelper(uint256 version, address newHelper) external onlyAdmin {
    require(newHelper != address(0), "Helper cannot be zero address");
    require(version > 0, "Version must be greater than 0");
    require((address)(helpers[version]) == address(0), "Helper already exists for version");
    helpers[version] = ZKPassportHelper(newHelper);
    emit HelperAdded(version, newHelper);
  }

  /**
   * @notice Removes a specific version of a helper
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
   * @notice Updates a specific version of a helper
   * @param version The version number
   * @param newHelper The address of the new helper
   */
  function updateHelper(uint256 version, address newHelper) external onlyAdmin {
    require(version > 0, "Version must be greater than 0");
    require(newHelper != address(0), "Helper cannot be zero address");
    require((address)(helpers[version]) != address(0), "Helper not found for version");
    address oldHelper = address(helpers[version]);
    helpers[version] = ZKPassportHelper(newHelper);
    emit HelperUpdated(version, oldHelper, newHelper);
  }


  function setPaused(bool _paused) external onlyGuardian {
    paused = _paused;
    emit PausedStatusChanged(_paused);
  }
}
