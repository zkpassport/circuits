// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {ZKPassportVerifier} from "../src/ZKPassportVerifier.sol";
import {IVerifier, HonkVerifier} from "../src/OuterCount4.sol";

contract ZKPassportVerifierTest is Test {
    IVerifier public verifier;
    ZKPassportVerifier public zkPassportVerifier;
    
    // Path to the proof file - using files directly in project root
    string constant PROOF_PATH = "./test/fixtures/valid_proof.hex";
    string constant PUBLIC_INPUTS_PATH = "./test/fixtures/valid_public_inputs.json";
    string constant COMMITTED_INPUTS_PATH = "./test/fixtures/valid_committed_inputs.hex";
    bytes32 constant VKEY_HASH = bytes32(uint256(0x8eb40d971a28de3157941b06eca6a9d97984855c415e1e6759b2c0f03b5540));

    function setUp() public {
        // Deploy the ZKPassportVerifier
        zkPassportVerifier = new ZKPassportVerifier();
        // Deploy the UltraHonkVerifier
        verifier = new HonkVerifier();

        // Add the verifier to the ZKPassportVerifier
        bytes32[] memory vkeyHashes = new bytes32[](1);
        vkeyHashes[0] = VKEY_HASH;
        address[] memory verifiers = new address[](1);
        verifiers[0] = address(verifier);
        zkPassportVerifier.addVerifiers(vkeyHashes, verifiers);
    }

    /**
     * @dev Helper function to load proof data from a file
     */
    function loadBytesFromFile(string memory filePath) internal returns (bytes memory) {
        // Try to read the file as a string
        string memory proofHex;
        
        try vm.readFile(filePath) returns (string memory content) {
            proofHex = content;
            
            // Check if content starts with 0x
            if (bytes(proofHex).length > 2 && bytes(proofHex)[0] == "0" && bytes(proofHex)[1] == "x") {
                proofHex = slice(proofHex, 2, bytes(proofHex).length - 2);
            }
            
            // Try to parse the bytes
            try vm.parseBytes(proofHex) returns (bytes memory parsedBytes) {
                return parsedBytes;
            } catch Error(string memory reason) {
                revert("Failed to parse proof bytes");
            } catch {
                revert("Failed to parse proof bytes");
            }
        } catch Error(string memory reason) {
            revert("Failed to load proof from file");
        } catch {
            revert("Failed to load proof from file");
        }
    }

    /**
     * @dev Helper function to load public inputs from a file
     */
    function loadBytes32FromFile(string memory filePath) internal returns (bytes32[] memory) {
        try vm.readFile(filePath) returns (string memory inputsJson) {
            // Parse the inputs from the file
            string[] memory inputs = vm.parseJsonStringArray(inputsJson, ".inputs");
            bytes32[] memory result = new bytes32[](inputs.length);
            
            for (uint i = 0; i < inputs.length; i++) {
                result[i] = vm.parseBytes32(inputs[i]);
            }
            
            return result;
        } catch Error(string memory reason) {
            revert("Failed to load inputs from file");
        } catch {
            revert("Failed to load inputs from file");
        }
    }

    /**
     * @dev Helper function to slice a string
     */
    function slice(string memory s, uint start, uint length) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        require(start + length <= b.length, "String slice out of bounds");
        
        bytes memory result = new bytes(length);
        for (uint i = 0; i < length; i++) {
            result[i] = b[start + i];
        }
        
        return string(result);
    }

    function test_VerifyValidProof() public {
        // Load proof and public inputs from files
        bytes memory proof = loadBytesFromFile(PROOF_PATH);
        bytes32[] memory publicInputs = loadBytes32FromFile(PUBLIC_INPUTS_PATH);
        bytes memory committedInputs = loadBytesFromFile(COMMITTED_INPUTS_PATH);
        // Contains in order the number of bytes of committed inputs for each disclosure proofs
        // that was verified by the final recursive proof
        uint256[] memory committedInputCounts = new uint256[](1);
        committedInputCounts[0] = 180;

        // Verify the proof
        vm.startSnapshotGas("ZKPassportVerifier verifyProof");
        (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(VKEY_HASH, proof, publicInputs, committedInputs, committedInputCounts, 2);
        uint256 gasUsed = vm.stopSnapshotGas();
        console.log("Gas used in ZKPassportVerifier verifyProof");
        console.log(gasUsed);
        assertEq(result, true);
        assertEq(scopedNullifier, bytes32(0x166e45d330ee09cdfd9584800d692caf5c89bafa9c756ddb07efe5a937311f36));
    }
}
