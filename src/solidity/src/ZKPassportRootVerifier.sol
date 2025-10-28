// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {IZKPassportVerifier, ProofVerificationParams} from "./Types.sol";

contract ZKPassportRootVerifier {
  address public admin;
  address public guardian;
  bool public paused;

  IZKPassportVerifier public verifier;

  // Events
  event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
  event GuardianUpdated(address indexed oldGuardian, address indexed newGuardian);
  event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
  event PausedStatusChanged(bool paused);

  /**
   * @dev Constructor
   * @param _admin The address of the admin
   * @param _guardian The address of the guardian
   * @param _verifier The address of the ZKPassport verifier implementation
   */
  constructor(address _admin, address _guardian, address _verifier) {
    require(_admin != address(0), "Admin cannot be zero address");
    admin = _admin;
    guardian = _guardian;
    verifier = IZKPassportVerifier(_verifier);
  }

  /**
   * @notice Verifies a ZKPassport proof
   * @param params The proof verification parameters
   * @return valid True if the proof is valid or false otherwise
   * @return uniqueIdentifier The unique identifier associated with the ID used to generate the proof
   */
  function verify(
    ProofVerificationParams calldata params
  ) external view whenNotPaused returns (bool valid, bytes32 uniqueIdentifier) {
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

  function setVerifier(address newVerifier) external onlyAdmin {
    address oldVerifier = address(verifier);
    verifier = IZKPassportVerifier(newVerifier);
    emit VerifierUpdated(oldVerifier, newVerifier);
  }

  function setPaused(bool _paused) external onlyGuardian {
    paused = _paused;
    emit PausedStatusChanged(_paused);
  }
}
