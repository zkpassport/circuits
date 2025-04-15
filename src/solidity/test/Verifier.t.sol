// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {IVerifier, HonkVerifier} from "../src/OuterCount4.sol";

contract CounterTest is Test {
    IVerifier public verifier;
    
    // Path to the proof file - using files directly in project root
    string constant PROOF_PATH = "./test/fixtures/valid_proof.hex";
    string constant PUBLIC_INPUTS_PATH = "./test/fixtures/valid_public_inputs.json";

    function setUp() public {
        verifier = new HonkVerifier();
    }

    /**
     * @dev Helper function to load proof data from a file
     */
    function loadProofFromFile(string memory filePath) internal returns (bytes memory) {
        console.log("Attempting to load proof from file:", filePath);
        
        // Try to read the file as a string
        string memory proofHex;
        
        try vm.readFile(filePath) returns (string memory content) {
            proofHex = content;
            console.log("Successfully read file, content length:", bytes(proofHex).length);
            
            // Check if content starts with 0x
            if (bytes(proofHex).length > 2 && bytes(proofHex)[0] == "0" && bytes(proofHex)[1] == "x") {
                console.log("Removing 0x prefix from proof");
                proofHex = slice(proofHex, 2, bytes(proofHex).length - 2);
            }
            
            // Try to parse the bytes
            try vm.parseBytes(proofHex) returns (bytes memory parsedBytes) {
                console.log("Successfully parsed bytes, length:", parsedBytes.length);
                return parsedBytes;
            } catch Error(string memory reason) {
                console.log("Error parsing bytes:", reason);
                revert("Failed to parse proof bytes");
            } catch {
                console.log("Unknown error parsing bytes");
                revert("Failed to parse proof bytes");
            }
        } catch Error(string memory reason) {
            console.log("Error reading file:", reason);
            revert("Failed to load proof from file");
        } catch {
            console.log("Unknown error reading file");
            revert("Failed to load proof from file");
        }
    }

    /**
     * @dev Helper function to load public inputs from a file
     */
    function loadPublicInputsFromFile(string memory filePath) internal returns (bytes32[] memory) {
        console.log("Attempting to load public inputs from file:", filePath);
        try vm.readFile(filePath) returns (string memory inputsJson) {
            console.log("Successfully read public inputs file, content length:", bytes(inputsJson).length);
            // Parse the inputs from the file
            string[] memory inputs = vm.parseJsonStringArray(inputsJson, ".inputs");
            bytes32[] memory result = new bytes32[](inputs.length);
            
            for (uint i = 0; i < inputs.length; i++) {
                result[i] = vm.parseBytes32(inputs[i]);
            }
            
            return result;
        } catch Error(string memory reason) {
            console.log("Error reading public inputs file:", reason);
            revert("Failed to load public inputs from file");
        } catch {
            console.log("Unknown error reading public inputs file");
            revert("Failed to load public inputs from file");
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
        bytes memory proof = loadProofFromFile(PROOF_PATH);
        bytes32[] memory publicInputs = loadPublicInputsFromFile(PUBLIC_INPUTS_PATH);

        // Verify the proof
        bool result = verifier.verify(proof, publicInputs);
        assertEq(result, true);
    }

    /**
     * @dev Test with a properly sized but mathematically invalid proof
     * We expect verification to revert with SumcheckFailed
     */
    function test_VerifyWithDummyProof() public {
        // Create a dummy proof with the exact required size (440 * 32 = 14080 bytes)
        bytes memory proof = new bytes(14080);
        
        // Generate some random values for the proof
        for (uint i = 0; i < 14080; i++) {
            proof[i] = bytes1(uint8(i % 256));
        }
        
        // Create a dummy public inputs array with the required size (29)
        bytes32[] memory publicInputs = new bytes32[](29);
        
        // Fill with some values
        for (uint i = 0; i < 29; i++) {
            publicInputs[i] = bytes32(uint256(i));
        }
        
        // Expect the SumcheckFailed error
        vm.expectRevert("SumcheckFailed()");
        verifier.verify(proof, publicInputs);
    }

    /**
     * @dev Test with an incorrectly sized proof
     * We expect it to revert with ProofLengthWrong
     */
    function test_VerifyInvalidProofLength() public {
        vm.expectRevert("ProofLengthWrong()");
        verifier.verify(bytes(""), new bytes32[](0));
    }
}
