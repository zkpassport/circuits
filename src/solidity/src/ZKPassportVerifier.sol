// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {IVerifier} from "../src/OuterCount4.sol";
import {DateUtils} from "../src/DateUtils.sol";

contract ZKPassportVerifier {
    address public admin;
    bool public paused;

    mapping(bytes32 => address) public vkeyHashToVerifier;

    // Events
    event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
    event PausedStatusChanged(bool paused);
    event ZKPassportVerifierDeployed(address indexed admin, uint256 timestamp);
    event VerifierAdded(bytes32 indexed vkeyHash, address indexed verifier);
    event VerifierRemoved(bytes32 indexed vkeyHash);

    /**
     * @dev Constructor
     */
    constructor() {
        admin = msg.sender;
        emit ZKPassportVerifierDeployed(admin, block.timestamp);
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized: admin only");
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

    function addVerifiers(bytes32[] calldata vkeyHashes, address[] calldata verifiers) external onlyAdmin whenNotPaused {
        for (uint256 i = 0; i < vkeyHashes.length; i++) {
            vkeyHashToVerifier[vkeyHashes[i]] = verifiers[i];
            emit VerifierAdded(vkeyHashes[i], verifiers[i]);
        }
    }

    function removeVerifiers(bytes32[] calldata vkeyHashes) external onlyAdmin whenNotPaused {
        for (uint256 i = 0; i < vkeyHashes.length; i++) {
            delete vkeyHashToVerifier[vkeyHashes[i]];
            emit VerifierRemoved(vkeyHashes[i]);
        }
    }

    function checkDate(bytes32[] memory publicInputs, uint256 validityPeriodInDays) internal view returns (bool) {
        bytes32[] memory currentDate = new bytes32[](8);
        for (uint256 i = 1; i < 9; i++) {
            currentDate[i - 1] = publicInputs[i];
        }
        return DateUtils.isDateValid(currentDate, validityPeriodInDays);
    }

    function verifyCommittedInputs(bytes32[] memory paramCommitments, bytes calldata committedInputs, uint256[] memory committedInputCounts) internal view returns (bool) {
        uint256 offset = 0;
        for (uint256 i = 0; i < committedInputCounts.length; i++) {
            // One byte is dropped inside the circuit as BN254 is limited to 254 bits
            bytes32 calculatedCommitment = sha256(abi.encodePacked(committedInputs[offset:offset + committedInputCounts[i]])) >> 8;
            require(calculatedCommitment == paramCommitments[i], "Invalid commitment");
            offset += committedInputCounts[i];
        }
        return true;
    }

    function verifyProof(
        bytes32 vkeyHash,
        bytes calldata proof, 
        bytes32[] calldata publicInputs, 
        bytes calldata committedInputs, 
        uint256[] calldata committedInputCounts, 
        uint256 validityPeriodInDays
    ) external view returns (bool, bytes32) {
        address verifier = vkeyHashToVerifier[vkeyHash];
        require(verifier != address(0), "Verifier not found");
        // We remove the last 16 public inputs from the count cause they are part of the aggregation object
        // and not the actual public inputs of the circuit
        uint256 actualPublicInputCount = publicInputs.length - 16;
        // TODO: verify the certificate registry root
        // bytes32 certificateRegistryRoot = publicInputs[0];
        // Checks the date of the proof
        require(checkDate(publicInputs, validityPeriodInDays), "Proof expired or date is invalid");
        // Extracts the commitments from the public inputs
        bytes32[] memory paramCommitments = new bytes32[](actualPublicInputCount - 12);
        for (uint256 i = 11; i < actualPublicInputCount - 1; i++) {
            paramCommitments[i - 11] = publicInputs[i];
        }
        // Verifies the commitments against the committed inputs
        require(verifyCommittedInputs(paramCommitments, committedInputs, committedInputCounts), "Invalid committed inputs");
        // Verifies the proof
        return (IVerifier(verifier).verify(proof, publicInputs), publicInputs[actualPublicInputCount - 1]);
    }
}