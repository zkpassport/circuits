// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Aztec
pragma solidity >=0.8.21;

uint256 constant N = 8388608;
uint256 constant LOG_N = 23;
uint256 constant NUMBER_OF_PUBLIC_INPUTS = 33;
library HonkVerificationKey {
    function loadVerificationKey() internal pure returns (Honk.VerificationKey memory) {
        Honk.VerificationKey memory vk = Honk.VerificationKey({
            circuitSize: uint256(8388608),
            logCircuitSize: uint256(23),
            publicInputsSize: uint256(33),
            ql: Honk.G1Point({ 
               x: uint256(0x136151add3cbfdb458d38da20943f74d66dc6d3498b26a56cb9ebf10475dc7e3),
               y: uint256(0x24564770a3e2bfafbd3927dce710f596447a6535e1651eba10d82c0e0ddde440)
            }),
            qr: Honk.G1Point({ 
               x: uint256(0x0fce23e6c3b152486a80f469fc335bee705a7ca3ad6eb5559acbf58d3125db92),
               y: uint256(0x19b450d780b83c25d9fc1ba7c0e7a5f6d42c78a004fce03efd8934559ed864c5)
            }),
            qo: Honk.G1Point({ 
               x: uint256(0x0fd9488853b26bced74ba535aefb1d51f476976feff70fa4d3cf704168a4a44f),
               y: uint256(0x21424c33c4dfca28072e5a3a6601925e1ea0bc7b9d69db8f45395db39fefc297)
            }),
            q4: Honk.G1Point({ 
               x: uint256(0x02777fd630aeadfe836baf76556d2dcefc214cb26f5560444e6a7f1c503f404f),
               y: uint256(0x2b030b64353d66d5b0cc5a13bef0eece82f6ec7c7f5a0aa1c9e9bb3a65c12d0c)
            }),
            qm: Honk.G1Point({ 
               x: uint256(0x0799407567600a83b819bb7784baaad252f12885cb7beec58a51063f1a2b52e8),
               y: uint256(0x2aa7f75fdc92bd863da4ca6a60607db949c7d1c5ae6d166973e59f908ed68999)
            }),
            qc: Honk.G1Point({ 
               x: uint256(0x028e89964de81340927b693da40a197d2688a034986fb912374001af47da7c53),
               y: uint256(0x2441ef9ddc8d31919e90118e8c03873e2d228d37e4e88a7275b0d0e0cb38c78b)
            }),
            qLookup: Honk.G1Point({ 
               x: uint256(0x23518e06ba26253840b60be25051fce0d1c8454a0f837c45dd283f01d5cefb18),
               y: uint256(0x0624f79a08ac099868fcd4d8e5e2d2386b4de6262ba77093974e51b47f2e9d53)
            }),
            qArith: Honk.G1Point({ 
               x: uint256(0x249c08ac3cf71c3c2266996a59133b181c4603c471456347af43e2161d276711),
               y: uint256(0x1d81de0a9ea42facca2dbff632c87b321e49039d5b191bb69069937d14b40b7d)
            }),
            qDeltaRange: Honk.G1Point({ 
               x: uint256(0x28f700b586d48f93e8f0d1b39214c252bb072bbd9cd1edcb6d74b99fef9379e3),
               y: uint256(0x21be6c3f9736365c8475e9a79c61fe5d69052b90424606343146ea183188631f)
            }),
            qElliptic: Honk.G1Point({ 
               x: uint256(0x213bc7415d4a7bce0459ccda6aae701237c5682ab39f41ad5e0cab33a5066b29),
               y: uint256(0x0771d9f286fe8c1a688fbc875aa96299bc86c2b0c5cde1896b747df16dceeb3d)
            }),
            qMemory: Honk.G1Point({ 
               x: uint256(0x123b28e9735c42a21b065f62f2cd8777d79722dca1595255aad965ede732b6a8),
               y: uint256(0x07f9731d4a7c80269c076f42a07446e77a74053c260bc7abffe21b91e573736f)
            }),
            qNnf: Honk.G1Point({ 
               x: uint256(0x1912dbc2bca74a0fd077a918b4b42ddca2654e7b042529b7bbe594f5020d825c),
               y: uint256(0x0fabb33bd614c6894d928b2a9a3fa33aa583456e856df7797250c85eeccc7beb)
            }),
            qPoseidon2External: Honk.G1Point({ 
               x: uint256(0x0a34c5faddab3db8bf09e861b4a475177f28e49b57b4f90526af6b4c8dc084b4),
               y: uint256(0x10f3178536fd59a8c1b594ad5ccb5adce079e1924cb305fc6853f43ee23816b4)
            }),
            qPoseidon2Internal: Honk.G1Point({ 
               x: uint256(0x2c1599af1cc2fe87006223af5ca7c445480c894b0c3e6d433d389530e8a414e5),
               y: uint256(0x1f48270d857c9ac63820b5fb73e02d16ad0f161014428d1bb7d8f216e155644f)
            }),
            s1: Honk.G1Point({ 
               x: uint256(0x2c9ad93a4eb2e541d0fac37e7b6718476397c3dddfdf1d843717ade325cfc529),
               y: uint256(0x0e9374c09381fa6290efbe0e77881da94c9fe7473dfe585e2b98639c6769435c)
            }),
            s2: Honk.G1Point({ 
               x: uint256(0x01a2a7a86222f8589b28931b6871463216696fbdae0daab5112e5c78b7ada3b0),
               y: uint256(0x00df311f076f8605f236141009cadedfdf07606fa1660790af3be15d34ccc529)
            }),
            s3: Honk.G1Point({ 
               x: uint256(0x2b8981145700bf3f5740438cdbf699f07a7bbda4b80332ae291738bb773988c1),
               y: uint256(0x0b15f59c8041e7718f0ec4c20f7b9fe9ce09deaa93037dcb0c7eff0713398eb7)
            }),
            s4: Honk.G1Point({ 
               x: uint256(0x072eb38db11dcee5d52aca283ea08880fb26c94b2b62cbc106cf0a34f7e5619f),
               y: uint256(0x2b3ab5cd047a0277b5516618c915bd02b330d6cf9c4c0c615b7f999a1b929dfb)
            }),
            t1: Honk.G1Point({ 
               x: uint256(0x1a89525c72408fa513a0e1c8dba5a05fee1321fcf12ac8a74656503decab2b30),
               y: uint256(0x036509a15bc0ccb2559b6acbc32e13ca563fb47f3588931305c50827096d2ac4)
            }),
            t2: Honk.G1Point({ 
               x: uint256(0x300e71228e5e502ff4c55c1fd62304464fa8e2d1ea61d8183dd09b9ea34154fa),
               y: uint256(0x2048ee8d9c585a6432d58c9c2aa9ea305f3bfb082ecf5ca6e2f88c8c8624c832)
            }),
            t3: Honk.G1Point({ 
               x: uint256(0x0e5c9ab127ca494b0bdfea1b40a724ebdf2361668026b4a55a2838ed168f454b),
               y: uint256(0x1c4575008292782776f1b24a43f467ecb99996501b0642274d1c7f53c983fda5)
            }),
            t4: Honk.G1Point({ 
               x: uint256(0x0faa5ac63ec27a827110f5f87c0833f6e6d33e6575214f524a8cdbab6c9be5e4),
               y: uint256(0x0ef3d4c2b14e96f1b74d9bd3a688b14f9fe1e07ea4877f47eb3970f3bc9c3c96)
            }),
            id1: Honk.G1Point({ 
               x: uint256(0x1ba6e1c7f0331410c41e207eaac76c834dc255218671b699920742fcbaac8a73),
               y: uint256(0x1aa59eaf61a717c2d0f351c16da7f0db0e9b834d0d72fbe0a52cc330f2829284)
            }),
            id2: Honk.G1Point({ 
               x: uint256(0x0061fa8f892ed60fefc4e7ff82a2703265daed4c77016c1ecb0997dfc62fab9e),
               y: uint256(0x16e5ebd700ba7f122189ae5274e5e6a6b9c16a2a4a4c43458b52dc6418b54608)
            }),
            id3: Honk.G1Point({ 
               x: uint256(0x29cd1bb54af2d0633a1ee93269d0c2c31afef7eef886711fd89cd4373ff3b571),
               y: uint256(0x0d470f04439a7ae42c728aafd6e465d518d91e7d614fe3264d09ca4252c2858b)
            }),
            id4: Honk.G1Point({ 
               x: uint256(0x0cafe426bcc02737dda728481a29f3e30f531288b2d78ddfb5fff8314bc03460),
               y: uint256(0x0772678c1787b315c02180acc00baaba9efaef816224cf4adc069b3cedb2d03f)
            }),
            lagrangeFirst: Honk.G1Point({ 
               x: uint256(0x0000000000000000000000000000000000000000000000000000000000000001),
               y: uint256(0x0000000000000000000000000000000000000000000000000000000000000002)
            }),
            lagrangeLast: Honk.G1Point({ 
               x: uint256(0x12c6981fa135e155143e5b01873ac658b17f6e2a426ed0ce9ae4b97ad7a7c642),
               y: uint256(0x119df7eccb45e978e035b1d15fcf26fecdf742ee8b4c12f8ebd8249a55bbf800)
            })
        });
        return vk;
    }
}

pragma solidity ^0.8.27;

interface IVerifier {
    function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external view returns (bool);
}

type Fr is uint256;

using {add as +} for Fr global;
using {sub as -} for Fr global;
using {mul as *} for Fr global;

using {exp as ^} for Fr global;
using {notEqual as !=} for Fr global;
using {equal as ==} for Fr global;

uint256 constant SUBGROUP_SIZE = 256;
uint256 constant MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617; // Prime field order
uint256 constant P = MODULUS;
Fr constant SUBGROUP_GENERATOR = Fr.wrap(0x07b0c561a6148404f086204a9f36ffb0617942546750f230c893619174a57a76);
Fr constant SUBGROUP_GENERATOR_INVERSE = Fr.wrap(0x204bd3277422fad364751ad938e2b5e6a54cf8c68712848a692c553d0329f5d6);
Fr constant MINUS_ONE = Fr.wrap(MODULUS - 1);
Fr constant ONE = Fr.wrap(1);
Fr constant ZERO = Fr.wrap(0);
// Instantiation

library FrLib {
    function from(uint256 value) internal pure returns (Fr) {
        return Fr.wrap(value % MODULUS);
    }

    function fromBytes32(bytes32 value) internal pure returns (Fr) {
        return Fr.wrap(uint256(value) % MODULUS);
    }

    function toBytes32(Fr value) internal pure returns (bytes32) {
        return bytes32(Fr.unwrap(value));
    }

    function invert(Fr value) internal view returns (Fr) {
        uint256 v = Fr.unwrap(value);
        uint256 result;

        // Call the modexp precompile to invert in the field
        assembly {
            let free := mload(0x40)
            mstore(free, 0x20)
            mstore(add(free, 0x20), 0x20)
            mstore(add(free, 0x40), 0x20)
            mstore(add(free, 0x60), v)
            mstore(add(free, 0x80), sub(MODULUS, 2)) 
            mstore(add(free, 0xa0), MODULUS)
            let success := staticcall(gas(), 0x05, free, 0xc0, 0x00, 0x20)
            if iszero(success) {
                revert(0, 0)
            }
            result := mload(0x00)
        }

        return Fr.wrap(result);
    }

    function pow(Fr base, uint256 v) internal view returns (Fr) {
        uint256 b = Fr.unwrap(base);
        uint256 result;

        // Call the modexp precompile to invert in the field
        assembly {
            let free := mload(0x40)
            mstore(free, 0x20)
            mstore(add(free, 0x20), 0x20)
            mstore(add(free, 0x40), 0x20)
            mstore(add(free, 0x60), b)
            mstore(add(free, 0x80), v) 
            mstore(add(free, 0xa0), MODULUS)
            let success := staticcall(gas(), 0x05, free, 0xc0, 0x00, 0x20)
            if iszero(success) {
                revert(0, 0)
            }
            result := mload(0x00)
        }

        return Fr.wrap(result);
    }

    function div(Fr numerator, Fr denominator) internal view returns (Fr) {
        return numerator * invert(denominator);
    }

    function sqr(Fr value) internal pure returns (Fr) {
        return value * value;
    }

    function unwrap(Fr value) internal pure returns (uint256) {
        return Fr.unwrap(value);
    }

    function neg(Fr value) internal pure returns (Fr) {
        return Fr.wrap(MODULUS - Fr.unwrap(value));
    }
}

// Free functions
function add(Fr a, Fr b) pure returns (Fr) {
    return Fr.wrap(addmod(Fr.unwrap(a), Fr.unwrap(b), MODULUS));
}

function mul(Fr a, Fr b) pure returns (Fr) {
    return Fr.wrap(mulmod(Fr.unwrap(a), Fr.unwrap(b), MODULUS));
}

function sub(Fr a, Fr b) pure returns (Fr) {
    return Fr.wrap(addmod(Fr.unwrap(a), MODULUS - Fr.unwrap(b), MODULUS));
}

function exp(Fr base, Fr exponent) pure returns (Fr) {
    if (Fr.unwrap(exponent) == 0) return Fr.wrap(1);
    // Implement exponent with a loop as we will overflow otherwise
    for (uint256 i = 1; i < Fr.unwrap(exponent); i += i) {
        base = base * base;
    }
    return base;
}

function notEqual(Fr a, Fr b) pure returns (bool) {
    return Fr.unwrap(a) != Fr.unwrap(b);
}

function equal(Fr a, Fr b) pure returns (bool) {
    return Fr.unwrap(a) == Fr.unwrap(b);
}

uint256 constant CONST_PROOF_SIZE_LOG_N = 28;

uint256 constant NUMBER_OF_SUBRELATIONS = 28;
uint256 constant BATCHED_RELATION_PARTIAL_LENGTH = 8;
uint256 constant ZK_BATCHED_RELATION_PARTIAL_LENGTH = 9;
uint256 constant NUMBER_OF_ENTITIES = 41;
uint256 constant NUMBER_UNSHIFTED = 36;
uint256 constant NUMBER_TO_BE_SHIFTED = 5;
uint256 constant PAIRING_POINTS_SIZE = 16;

// Alphas are used as relation separators so there should be NUMBER_OF_SUBRELATIONS - 1
uint256 constant NUMBER_OF_ALPHAS = NUMBER_OF_SUBRELATIONS - 1;

// ENUM FOR WIRES
enum WIRE {
    Q_M,
    Q_C,
    Q_L,
    Q_R,
    Q_O,
    Q_4,
    Q_LOOKUP,
    Q_ARITH,
    Q_RANGE,
    Q_ELLIPTIC,
    Q_MEMORY,
    Q_NNF,
    Q_POSEIDON2_EXTERNAL,
    Q_POSEIDON2_INTERNAL,
    SIGMA_1,
    SIGMA_2,
    SIGMA_3,
    SIGMA_4,
    ID_1,
    ID_2,
    ID_3,
    ID_4,
    TABLE_1,
    TABLE_2,
    TABLE_3,
    TABLE_4,
    LAGRANGE_FIRST,
    LAGRANGE_LAST,
    W_L,
    W_R,
    W_O,
    W_4,
    Z_PERM,
    LOOKUP_INVERSES,
    LOOKUP_READ_COUNTS,
    LOOKUP_READ_TAGS,
    W_L_SHIFT,
    W_R_SHIFT,
    W_O_SHIFT,
    W_4_SHIFT,
    Z_PERM_SHIFT
}

library Honk {
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G1ProofPoint {
        uint256 x_0;
        uint256 x_1;
        uint256 y_0;
        uint256 y_1;
    }

    struct VerificationKey {
        // Misc Params
        uint256 circuitSize;
        uint256 logCircuitSize;
        uint256 publicInputsSize;
        // Selectors
        G1Point qm;
        G1Point qc;
        G1Point ql;
        G1Point qr;
        G1Point qo;
        G1Point q4;
        G1Point qLookup; // Lookup
        G1Point qArith; // Arithmetic widget
        G1Point qDeltaRange; // Delta Range sort
        G1Point qMemory; // Memory
        G1Point qNnf; // Non-native Field
        G1Point qElliptic; // Auxillary
        G1Point qPoseidon2External;
        G1Point qPoseidon2Internal;
        // Copy cnstraints
        G1Point s1;
        G1Point s2;
        G1Point s3;
        G1Point s4;
        // Copy identity
        G1Point id1;
        G1Point id2;
        G1Point id3;
        G1Point id4;
        // Precomputed lookup table
        G1Point t1;
        G1Point t2;
        G1Point t3;
        G1Point t4;
        // Fixed first and last
        G1Point lagrangeFirst;
        G1Point lagrangeLast;
    }

    struct RelationParameters {
        // challenges
        Fr eta;
        Fr etaTwo;
        Fr etaThree;
        Fr beta;
        Fr gamma;
        // derived
        Fr publicInputsDelta;
    }

    struct Proof {
        // Pairing point object
        Fr[PAIRING_POINTS_SIZE] pairingPointObject;
        // Free wires
        Honk.G1ProofPoint w1;
        Honk.G1ProofPoint w2;
        Honk.G1ProofPoint w3;
        Honk.G1ProofPoint w4;
        // Lookup helpers - Permutations
        Honk.G1ProofPoint zPerm;
        // Lookup helpers - logup
        Honk.G1ProofPoint lookupReadCounts;
        Honk.G1ProofPoint lookupReadTags;
        Honk.G1ProofPoint lookupInverses;
        // Sumcheck
        Fr[BATCHED_RELATION_PARTIAL_LENGTH][CONST_PROOF_SIZE_LOG_N] sumcheckUnivariates;
        Fr[NUMBER_OF_ENTITIES] sumcheckEvaluations;
        // Shplemini
        Honk.G1ProofPoint[CONST_PROOF_SIZE_LOG_N - 1] geminiFoldComms;
        Fr[CONST_PROOF_SIZE_LOG_N] geminiAEvaluations;
        Honk.G1ProofPoint shplonkQ;
        Honk.G1ProofPoint kzgQuotient;
    }

    struct ZKProof {
        // Pairing point object
        Fr[PAIRING_POINTS_SIZE] pairingPointObject;
        // Commitments to wire polynomials
        Honk.G1ProofPoint w1;
        Honk.G1ProofPoint w2;
        Honk.G1ProofPoint w3;
        Honk.G1ProofPoint w4;
        // Commitments to logup witness polynomials
        Honk.G1ProofPoint lookupReadCounts;
        Honk.G1ProofPoint lookupReadTags;
        Honk.G1ProofPoint lookupInverses;
        // Commitment to grand permutation polynomial
        Honk.G1ProofPoint zPerm;
        Honk.G1ProofPoint[3] libraCommitments;
        // Sumcheck
        Fr libraSum;
        Fr[ZK_BATCHED_RELATION_PARTIAL_LENGTH][CONST_PROOF_SIZE_LOG_N] sumcheckUnivariates;
        Fr[NUMBER_OF_ENTITIES] sumcheckEvaluations;
        Fr libraEvaluation;
        // ZK
        Honk.G1ProofPoint geminiMaskingPoly;
        Fr geminiMaskingEval;
        // Shplemini
        Honk.G1ProofPoint[CONST_PROOF_SIZE_LOG_N - 1] geminiFoldComms;
        Fr[CONST_PROOF_SIZE_LOG_N] geminiAEvaluations;
        Fr[4] libraPolyEvals;
        Honk.G1ProofPoint shplonkQ;
        Honk.G1ProofPoint kzgQuotient;
    }
}

// Transcript library to generate fiat shamir challenges
struct Transcript {
    // Oink
    Honk.RelationParameters relationParameters;
    Fr[NUMBER_OF_ALPHAS] alphas;
    Fr[CONST_PROOF_SIZE_LOG_N] gateChallenges;
    // Sumcheck
    Fr[CONST_PROOF_SIZE_LOG_N] sumCheckUChallenges;
    // Gemini
    Fr rho;
    Fr geminiR;
    // Shplonk
    Fr shplonkNu;
    Fr shplonkZ;
}

library TranscriptLib {
    function generateTranscript(
        Honk.Proof memory proof,
        bytes32[] calldata publicInputs,
        uint256 circuitSize,
        uint256 publicInputsSize,
        uint256 pubInputsOffset
    ) internal pure returns (Transcript memory t) {
        Fr previousChallenge;
        (t.relationParameters, previousChallenge) = generateRelationParametersChallenges(
            proof, publicInputs, circuitSize, publicInputsSize, pubInputsOffset, previousChallenge
        );

        (t.alphas, previousChallenge) = generateAlphaChallenges(previousChallenge, proof);

        (t.gateChallenges, previousChallenge) = generateGateChallenges(previousChallenge);

        (t.sumCheckUChallenges, previousChallenge) = generateSumcheckChallenges(proof, previousChallenge);

        (t.rho, previousChallenge) = generateRhoChallenge(proof, previousChallenge);

        (t.geminiR, previousChallenge) = generateGeminiRChallenge(proof, previousChallenge);

        (t.shplonkNu, previousChallenge) = generateShplonkNuChallenge(proof, previousChallenge);

        (t.shplonkZ, previousChallenge) = generateShplonkZChallenge(proof, previousChallenge);

        return t;
    }

    function splitChallenge(Fr challenge) internal pure returns (Fr first, Fr second) {
        uint256 challengeU256 = uint256(Fr.unwrap(challenge));
        uint256 lo = challengeU256 & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
        uint256 hi = challengeU256 >> 128;
        first = FrLib.fromBytes32(bytes32(lo));
        second = FrLib.fromBytes32(bytes32(hi));
    }

    function generateRelationParametersChallenges(
        Honk.Proof memory proof,
        bytes32[] calldata publicInputs,
        uint256 circuitSize,
        uint256 publicInputsSize,
        uint256 pubInputsOffset,
        Fr previousChallenge
    ) internal pure returns (Honk.RelationParameters memory rp, Fr nextPreviousChallenge) {
        (rp.eta, rp.etaTwo, rp.etaThree, previousChallenge) =
            generateEtaChallenge(proof, publicInputs, circuitSize, publicInputsSize, pubInputsOffset);

        (rp.beta, rp.gamma, nextPreviousChallenge) = generateBetaAndGammaChallenges(previousChallenge, proof);
    }

    function generateEtaChallenge(
        Honk.Proof memory proof,
        bytes32[] calldata publicInputs,
        uint256 circuitSize,
        uint256 publicInputsSize,
        uint256 pubInputsOffset
    ) internal pure returns (Fr eta, Fr etaTwo, Fr etaThree, Fr previousChallenge) {
        bytes32[] memory round0 = new bytes32[](3 + publicInputsSize + 12);
        round0[0] = bytes32(circuitSize);
        round0[1] = bytes32(publicInputsSize);
        round0[2] = bytes32(pubInputsOffset);

        for (uint256 i = 0; i < publicInputsSize - PAIRING_POINTS_SIZE; i++) {
            round0[3 + i] = bytes32(publicInputs[i]);
        }
        for (uint256 i = 0; i < PAIRING_POINTS_SIZE; i++) {
            round0[3 + publicInputsSize - PAIRING_POINTS_SIZE + i] = FrLib.toBytes32(proof.pairingPointObject[i]);
        }

        // Create the first challenge
        // Note: w4 is added to the challenge later on
        round0[3 + publicInputsSize] = bytes32(proof.w1.x_0);
        round0[3 + publicInputsSize + 1] = bytes32(proof.w1.x_1);
        round0[3 + publicInputsSize + 2] = bytes32(proof.w1.y_0);
        round0[3 + publicInputsSize + 3] = bytes32(proof.w1.y_1);
        round0[3 + publicInputsSize + 4] = bytes32(proof.w2.x_0);
        round0[3 + publicInputsSize + 5] = bytes32(proof.w2.x_1);
        round0[3 + publicInputsSize + 6] = bytes32(proof.w2.y_0);
        round0[3 + publicInputsSize + 7] = bytes32(proof.w2.y_1);
        round0[3 + publicInputsSize + 8] = bytes32(proof.w3.x_0);
        round0[3 + publicInputsSize + 9] = bytes32(proof.w3.x_1);
        round0[3 + publicInputsSize + 10] = bytes32(proof.w3.y_0);
        round0[3 + publicInputsSize + 11] = bytes32(proof.w3.y_1);

        previousChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(round0)));
        (eta, etaTwo) = splitChallenge(previousChallenge);

        previousChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(Fr.unwrap(previousChallenge))));
        Fr unused;
        (etaThree, unused) = splitChallenge(previousChallenge);
    }

    function generateBetaAndGammaChallenges(Fr previousChallenge, Honk.Proof memory proof)
        internal
        pure
        returns (Fr beta, Fr gamma, Fr nextPreviousChallenge)
    {
        bytes32[13] memory round1;
        round1[0] = FrLib.toBytes32(previousChallenge);
        round1[1] = bytes32(proof.lookupReadCounts.x_0);
        round1[2] = bytes32(proof.lookupReadCounts.x_1);
        round1[3] = bytes32(proof.lookupReadCounts.y_0);
        round1[4] = bytes32(proof.lookupReadCounts.y_1);
        round1[5] = bytes32(proof.lookupReadTags.x_0);
        round1[6] = bytes32(proof.lookupReadTags.x_1);
        round1[7] = bytes32(proof.lookupReadTags.y_0);
        round1[8] = bytes32(proof.lookupReadTags.y_1);
        round1[9] = bytes32(proof.w4.x_0);
        round1[10] = bytes32(proof.w4.x_1);
        round1[11] = bytes32(proof.w4.y_0);
        round1[12] = bytes32(proof.w4.y_1);

        nextPreviousChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(round1)));
        (beta, gamma) = splitChallenge(nextPreviousChallenge);
    }

    // Alpha challenges non-linearise the gate contributions
    function generateAlphaChallenges(Fr previousChallenge, Honk.Proof memory proof)
        internal
        pure
        returns (Fr[NUMBER_OF_ALPHAS] memory alphas, Fr nextPreviousChallenge)
    {
        // Generate the original sumcheck alpha 0 by hashing zPerm and zLookup
        uint256[9] memory alpha0;
        alpha0[0] = Fr.unwrap(previousChallenge);
        alpha0[1] = proof.lookupInverses.x_0;
        alpha0[2] = proof.lookupInverses.x_1;
        alpha0[3] = proof.lookupInverses.y_0;
        alpha0[4] = proof.lookupInverses.y_1;
        alpha0[5] = proof.zPerm.x_0;
        alpha0[6] = proof.zPerm.x_1;
        alpha0[7] = proof.zPerm.y_0;
        alpha0[8] = proof.zPerm.y_1;

        nextPreviousChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(alpha0)));
        (alphas[0], alphas[1]) = splitChallenge(nextPreviousChallenge);

        for (uint256 i = 1; i < NUMBER_OF_ALPHAS / 2; i++) {
            nextPreviousChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(Fr.unwrap(nextPreviousChallenge))));
            (alphas[2 * i], alphas[2 * i + 1]) = splitChallenge(nextPreviousChallenge);
        }
        if (((NUMBER_OF_ALPHAS & 1) == 1) && (NUMBER_OF_ALPHAS > 2)) {
            nextPreviousChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(Fr.unwrap(nextPreviousChallenge))));
            Fr unused;
            (alphas[NUMBER_OF_ALPHAS - 1], unused) = splitChallenge(nextPreviousChallenge);
        }
    }

    function generateGateChallenges(Fr previousChallenge)
        internal
        pure
        returns (Fr[CONST_PROOF_SIZE_LOG_N] memory gateChallenges, Fr nextPreviousChallenge)
    {
        for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N; i++) {
            previousChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(Fr.unwrap(previousChallenge))));
            Fr unused;
            (gateChallenges[i], unused) = splitChallenge(previousChallenge);
        }
        nextPreviousChallenge = previousChallenge;
    }

    function generateSumcheckChallenges(Honk.Proof memory proof, Fr prevChallenge)
        internal
        pure
        returns (Fr[CONST_PROOF_SIZE_LOG_N] memory sumcheckChallenges, Fr nextPreviousChallenge)
    {
        for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N; i++) {
            Fr[BATCHED_RELATION_PARTIAL_LENGTH + 1] memory univariateChal;
            univariateChal[0] = prevChallenge;

            for (uint256 j = 0; j < BATCHED_RELATION_PARTIAL_LENGTH; j++) {
                univariateChal[j + 1] = proof.sumcheckUnivariates[i][j];
            }
            prevChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(univariateChal)));
            Fr unused;
            (sumcheckChallenges[i], unused) = splitChallenge(prevChallenge);
        }
        nextPreviousChallenge = prevChallenge;
    }

    function generateRhoChallenge(Honk.Proof memory proof, Fr prevChallenge)
        internal
        pure
        returns (Fr rho, Fr nextPreviousChallenge)
    {
        Fr[NUMBER_OF_ENTITIES + 1] memory rhoChallengeElements;
        rhoChallengeElements[0] = prevChallenge;

        for (uint256 i = 0; i < NUMBER_OF_ENTITIES; i++) {
            rhoChallengeElements[i + 1] = proof.sumcheckEvaluations[i];
        }

        nextPreviousChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(rhoChallengeElements)));
        Fr unused;
        (rho, unused) = splitChallenge(nextPreviousChallenge);
    }

    function generateGeminiRChallenge(Honk.Proof memory proof, Fr prevChallenge)
        internal
        pure
        returns (Fr geminiR, Fr nextPreviousChallenge)
    {
        uint256[(CONST_PROOF_SIZE_LOG_N - 1) * 4 + 1] memory gR;
        gR[0] = Fr.unwrap(prevChallenge);

        for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N - 1; i++) {
            gR[1 + i * 4] = proof.geminiFoldComms[i].x_0;
            gR[2 + i * 4] = proof.geminiFoldComms[i].x_1;
            gR[3 + i * 4] = proof.geminiFoldComms[i].y_0;
            gR[4 + i * 4] = proof.geminiFoldComms[i].y_1;
        }

        nextPreviousChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(gR)));
        Fr unused;
        (geminiR, unused) = splitChallenge(nextPreviousChallenge);
    }

    function generateShplonkNuChallenge(Honk.Proof memory proof, Fr prevChallenge)
        internal
        pure
        returns (Fr shplonkNu, Fr nextPreviousChallenge)
    {
        uint256[(CONST_PROOF_SIZE_LOG_N) + 1] memory shplonkNuChallengeElements;
        shplonkNuChallengeElements[0] = Fr.unwrap(prevChallenge);

        for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N; i++) {
            shplonkNuChallengeElements[i + 1] = Fr.unwrap(proof.geminiAEvaluations[i]);
        }

        nextPreviousChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(shplonkNuChallengeElements)));
        Fr unused;
        (shplonkNu, unused) = splitChallenge(nextPreviousChallenge);
    }

    function generateShplonkZChallenge(Honk.Proof memory proof, Fr prevChallenge)
        internal
        pure
        returns (Fr shplonkZ, Fr nextPreviousChallenge)
    {
        uint256[5] memory shplonkZChallengeElements;
        shplonkZChallengeElements[0] = Fr.unwrap(prevChallenge);

        shplonkZChallengeElements[1] = proof.shplonkQ.x_0;
        shplonkZChallengeElements[2] = proof.shplonkQ.x_1;
        shplonkZChallengeElements[3] = proof.shplonkQ.y_0;
        shplonkZChallengeElements[4] = proof.shplonkQ.y_1;

        nextPreviousChallenge = FrLib.fromBytes32(keccak256(abi.encodePacked(shplonkZChallengeElements)));
        Fr unused;
        (shplonkZ, unused) = splitChallenge(nextPreviousChallenge);
    }

    function loadProof(bytes calldata proof) internal pure returns (Honk.Proof memory p) {
        uint256 boundary = 0x0;

        // Pairing point object
        for (uint256 i = 0; i < PAIRING_POINTS_SIZE; i++) {
            p.pairingPointObject[i] = bytesToFr(proof[boundary:boundary + 0x20]);
            boundary += 0x20;
        }
        // Commitments
        p.w1 = bytesToG1ProofPoint(proof[boundary:boundary + 0x80]);
        boundary += 0x80;
        p.w2 = bytesToG1ProofPoint(proof[boundary:boundary + 0x80]);
        boundary += 0x80;
        p.w3 = bytesToG1ProofPoint(proof[boundary:boundary + 0x80]);
        boundary += 0x80;

        // Lookup / Permutation Helper Commitments
        p.lookupReadCounts = bytesToG1ProofPoint(proof[boundary:boundary + 0x80]);
        boundary += 0x80;
        p.lookupReadTags = bytesToG1ProofPoint(proof[boundary:boundary + 0x80]);
        boundary += 0x80;
        p.w4 = bytesToG1ProofPoint(proof[boundary:boundary + 0x80]);
        boundary += 0x80;
        p.lookupInverses = bytesToG1ProofPoint(proof[boundary:boundary + 0x80]);
        boundary += 0x80;
        p.zPerm = bytesToG1ProofPoint(proof[boundary:boundary + 0x80]);
        boundary += 0x80;

        // Sumcheck univariates
        for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N; i++) {
            for (uint256 j = 0; j < BATCHED_RELATION_PARTIAL_LENGTH; j++) {
                p.sumcheckUnivariates[i][j] = bytesToFr(proof[boundary:boundary + 0x20]);
                boundary += 0x20;
            }
        }
        // Sumcheck evaluations
        for (uint256 i = 0; i < NUMBER_OF_ENTITIES; i++) {
            p.sumcheckEvaluations[i] = bytesToFr(proof[boundary:boundary + 0x20]);
            boundary += 0x20;
        }

        // Gemini
        // Read gemini fold univariates
        for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N - 1; i++) {
            p.geminiFoldComms[i] = bytesToG1ProofPoint(proof[boundary:boundary + 0x80]);
            boundary += 0x80;
        }

        // Read gemini a evaluations
        for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N; i++) {
            p.geminiAEvaluations[i] = bytesToFr(proof[boundary:boundary + 0x20]);
            boundary += 0x20;
        }

        // Shplonk
        p.shplonkQ = bytesToG1ProofPoint(proof[boundary:boundary + 0x80]);
        boundary += 0x80;
        // KZG
        p.kzgQuotient = bytesToG1ProofPoint(proof[boundary:boundary + 0x80]);
    }
}

// Field arithmetic libraries

library RelationsLib {
    Fr internal constant GRUMPKIN_CURVE_B_PARAMETER_NEGATED = Fr.wrap(17); // -(-17)

    function accumulateRelationEvaluations(
        Fr[NUMBER_OF_ENTITIES] memory purportedEvaluations,
        Honk.RelationParameters memory rp,
        Fr[NUMBER_OF_ALPHAS] memory alphas,
        Fr powPartialEval
    ) internal pure returns (Fr accumulator) {
        Fr[NUMBER_OF_SUBRELATIONS] memory evaluations;

        // Accumulate all relations in Ultra Honk - each with varying number of subrelations
        accumulateArithmeticRelation(purportedEvaluations, evaluations, powPartialEval);
        accumulatePermutationRelation(purportedEvaluations, rp, evaluations, powPartialEval);
        accumulateLogDerivativeLookupRelation(purportedEvaluations, rp, evaluations, powPartialEval);
        accumulateDeltaRangeRelation(purportedEvaluations, evaluations, powPartialEval);
        accumulateEllipticRelation(purportedEvaluations, evaluations, powPartialEval);
        accumulateMemoryRelation(purportedEvaluations, rp, evaluations, powPartialEval);
        accumulateNnfRelation(purportedEvaluations, rp, evaluations, powPartialEval);
        accumulatePoseidonExternalRelation(purportedEvaluations, evaluations, powPartialEval);
        accumulatePoseidonInternalRelation(purportedEvaluations, evaluations, powPartialEval);
        // batch the subrelations with the alpha challenges to obtain the full honk relation
        accumulator = scaleAndBatchSubrelations(evaluations, alphas);
    }

    /**
     * Aesthetic helper function that is used to index by enum into proof.sumcheckEvaluations, it avoids
     * the relation checking code being cluttered with uint256 type casting, which is often a different colour in code
     * editors, and thus is noisy.
     */
    function wire(Fr[NUMBER_OF_ENTITIES] memory p, WIRE _wire) internal pure returns (Fr) {
        return p[uint256(_wire)];
    }

    uint256 internal constant NEG_HALF_MODULO_P = 0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000;
    /**
     * Ultra Arithmetic Relation
     *
     */

    function accumulateArithmeticRelation(
        Fr[NUMBER_OF_ENTITIES] memory p,
        Fr[NUMBER_OF_SUBRELATIONS] memory evals,
        Fr domainSep
    ) internal pure {
        // Relation 0
        Fr q_arith = wire(p, WIRE.Q_ARITH);
        {
            Fr neg_half = Fr.wrap(NEG_HALF_MODULO_P);

            Fr accum = (q_arith - Fr.wrap(3)) * (wire(p, WIRE.Q_M) * wire(p, WIRE.W_R) * wire(p, WIRE.W_L)) * neg_half;
            accum = accum + (wire(p, WIRE.Q_L) * wire(p, WIRE.W_L)) + (wire(p, WIRE.Q_R) * wire(p, WIRE.W_R))
                + (wire(p, WIRE.Q_O) * wire(p, WIRE.W_O)) + (wire(p, WIRE.Q_4) * wire(p, WIRE.W_4)) + wire(p, WIRE.Q_C);
            accum = accum + (q_arith - ONE) * wire(p, WIRE.W_4_SHIFT);
            accum = accum * q_arith;
            accum = accum * domainSep;
            evals[0] = accum;
        }

        // Relation 1
        {
            Fr accum = wire(p, WIRE.W_L) + wire(p, WIRE.W_4) - wire(p, WIRE.W_L_SHIFT) + wire(p, WIRE.Q_M);
            accum = accum * (q_arith - Fr.wrap(2));
            accum = accum * (q_arith - ONE);
            accum = accum * q_arith;
            accum = accum * domainSep;
            evals[1] = accum;
        }
    }

    function accumulatePermutationRelation(
        Fr[NUMBER_OF_ENTITIES] memory p,
        Honk.RelationParameters memory rp,
        Fr[NUMBER_OF_SUBRELATIONS] memory evals,
        Fr domainSep
    ) internal pure {
        Fr grand_product_numerator;
        Fr grand_product_denominator;

        {
            Fr num = wire(p, WIRE.W_L) + wire(p, WIRE.ID_1) * rp.beta + rp.gamma;
            num = num * (wire(p, WIRE.W_R) + wire(p, WIRE.ID_2) * rp.beta + rp.gamma);
            num = num * (wire(p, WIRE.W_O) + wire(p, WIRE.ID_3) * rp.beta + rp.gamma);
            num = num * (wire(p, WIRE.W_4) + wire(p, WIRE.ID_4) * rp.beta + rp.gamma);

            grand_product_numerator = num;
        }
        {
            Fr den = wire(p, WIRE.W_L) + wire(p, WIRE.SIGMA_1) * rp.beta + rp.gamma;
            den = den * (wire(p, WIRE.W_R) + wire(p, WIRE.SIGMA_2) * rp.beta + rp.gamma);
            den = den * (wire(p, WIRE.W_O) + wire(p, WIRE.SIGMA_3) * rp.beta + rp.gamma);
            den = den * (wire(p, WIRE.W_4) + wire(p, WIRE.SIGMA_4) * rp.beta + rp.gamma);

            grand_product_denominator = den;
        }

        // Contribution 2
        {
            Fr acc = (wire(p, WIRE.Z_PERM) + wire(p, WIRE.LAGRANGE_FIRST)) * grand_product_numerator;

            acc = acc
                - (
                    (wire(p, WIRE.Z_PERM_SHIFT) + (wire(p, WIRE.LAGRANGE_LAST) * rp.publicInputsDelta))
                        * grand_product_denominator
                );
            acc = acc * domainSep;
            evals[2] = acc;
        }

        // Contribution 3
        {
            Fr acc = (wire(p, WIRE.LAGRANGE_LAST) * wire(p, WIRE.Z_PERM_SHIFT)) * domainSep;
            evals[3] = acc;
        }
    }

    function accumulateLogDerivativeLookupRelation(
        Fr[NUMBER_OF_ENTITIES] memory p,
        Honk.RelationParameters memory rp,
        Fr[NUMBER_OF_SUBRELATIONS] memory evals,
        Fr domainSep
    ) internal pure {
        Fr write_term;
        Fr read_term;

        // Calculate the write term (the table accumulation)
        {
            write_term = wire(p, WIRE.TABLE_1) + rp.gamma + (wire(p, WIRE.TABLE_2) * rp.eta)
                + (wire(p, WIRE.TABLE_3) * rp.etaTwo) + (wire(p, WIRE.TABLE_4) * rp.etaThree);
        }

        // Calculate the write term
        {
            Fr derived_entry_1 = wire(p, WIRE.W_L) + rp.gamma + (wire(p, WIRE.Q_R) * wire(p, WIRE.W_L_SHIFT));
            Fr derived_entry_2 = wire(p, WIRE.W_R) + wire(p, WIRE.Q_M) * wire(p, WIRE.W_R_SHIFT);
            Fr derived_entry_3 = wire(p, WIRE.W_O) + wire(p, WIRE.Q_C) * wire(p, WIRE.W_O_SHIFT);

            read_term = derived_entry_1 + (derived_entry_2 * rp.eta) + (derived_entry_3 * rp.etaTwo)
                + (wire(p, WIRE.Q_O) * rp.etaThree);
        }

        Fr read_inverse = wire(p, WIRE.LOOKUP_INVERSES) * write_term;
        Fr write_inverse = wire(p, WIRE.LOOKUP_INVERSES) * read_term;

        Fr inverse_exists_xor = wire(p, WIRE.LOOKUP_READ_TAGS) + wire(p, WIRE.Q_LOOKUP)
            - (wire(p, WIRE.LOOKUP_READ_TAGS) * wire(p, WIRE.Q_LOOKUP));

        // Inverse calculated correctly relation
        Fr accumulatorNone = read_term * write_term * wire(p, WIRE.LOOKUP_INVERSES) - inverse_exists_xor;
        accumulatorNone = accumulatorNone * domainSep;

        // Inverse
        Fr accumulatorOne = wire(p, WIRE.Q_LOOKUP) * read_inverse - wire(p, WIRE.LOOKUP_READ_COUNTS) * write_inverse;

        Fr read_tag = wire(p, WIRE.LOOKUP_READ_TAGS);

        Fr read_tag_boolean_relation = read_tag * read_tag - read_tag;

        evals[4] = accumulatorNone;
        evals[5] = accumulatorOne;
        evals[6] = read_tag_boolean_relation * domainSep;
    }

    function accumulateDeltaRangeRelation(
        Fr[NUMBER_OF_ENTITIES] memory p,
        Fr[NUMBER_OF_SUBRELATIONS] memory evals,
        Fr domainSep
    ) internal pure {
        Fr minus_one = ZERO - ONE;
        Fr minus_two = ZERO - Fr.wrap(2);
        Fr minus_three = ZERO - Fr.wrap(3);

        // Compute wire differences
        Fr delta_1 = wire(p, WIRE.W_R) - wire(p, WIRE.W_L);
        Fr delta_2 = wire(p, WIRE.W_O) - wire(p, WIRE.W_R);
        Fr delta_3 = wire(p, WIRE.W_4) - wire(p, WIRE.W_O);
        Fr delta_4 = wire(p, WIRE.W_L_SHIFT) - wire(p, WIRE.W_4);

        // Contribution 6
        {
            Fr acc = delta_1;
            acc = acc * (delta_1 + minus_one);
            acc = acc * (delta_1 + minus_two);
            acc = acc * (delta_1 + minus_three);
            acc = acc * wire(p, WIRE.Q_RANGE);
            acc = acc * domainSep;
            evals[7] = acc;
        }

        // Contribution 7
        {
            Fr acc = delta_2;
            acc = acc * (delta_2 + minus_one);
            acc = acc * (delta_2 + minus_two);
            acc = acc * (delta_2 + minus_three);
            acc = acc * wire(p, WIRE.Q_RANGE);
            acc = acc * domainSep;
            evals[8] = acc;
        }

        // Contribution 8
        {
            Fr acc = delta_3;
            acc = acc * (delta_3 + minus_one);
            acc = acc * (delta_3 + minus_two);
            acc = acc * (delta_3 + minus_three);
            acc = acc * wire(p, WIRE.Q_RANGE);
            acc = acc * domainSep;
            evals[9] = acc;
        }

        // Contribution 9
        {
            Fr acc = delta_4;
            acc = acc * (delta_4 + minus_one);
            acc = acc * (delta_4 + minus_two);
            acc = acc * (delta_4 + minus_three);
            acc = acc * wire(p, WIRE.Q_RANGE);
            acc = acc * domainSep;
            evals[10] = acc;
        }
    }

    struct EllipticParams {
        // Points
        Fr x_1;
        Fr y_1;
        Fr x_2;
        Fr y_2;
        Fr y_3;
        Fr x_3;
        // push accumulators into memory
        Fr x_double_identity;
    }

    function accumulateEllipticRelation(
        Fr[NUMBER_OF_ENTITIES] memory p,
        Fr[NUMBER_OF_SUBRELATIONS] memory evals,
        Fr domainSep
    ) internal pure {
        EllipticParams memory ep;
        ep.x_1 = wire(p, WIRE.W_R);
        ep.y_1 = wire(p, WIRE.W_O);

        ep.x_2 = wire(p, WIRE.W_L_SHIFT);
        ep.y_2 = wire(p, WIRE.W_4_SHIFT);
        ep.y_3 = wire(p, WIRE.W_O_SHIFT);
        ep.x_3 = wire(p, WIRE.W_R_SHIFT);

        Fr q_sign = wire(p, WIRE.Q_L);
        Fr q_is_double = wire(p, WIRE.Q_M);

        // Contribution 10 point addition, x-coordinate check
        // q_elliptic * (x3 + x2 + x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
        Fr x_diff = (ep.x_2 - ep.x_1);
        Fr y1_sqr = (ep.y_1 * ep.y_1);
        {
            // Move to top
            Fr partialEval = domainSep;

            Fr y2_sqr = (ep.y_2 * ep.y_2);
            Fr y1y2 = ep.y_1 * ep.y_2 * q_sign;
            Fr x_add_identity = (ep.x_3 + ep.x_2 + ep.x_1);
            x_add_identity = x_add_identity * x_diff * x_diff;
            x_add_identity = x_add_identity - y2_sqr - y1_sqr + y1y2 + y1y2;

            evals[11] = x_add_identity * partialEval * wire(p, WIRE.Q_ELLIPTIC) * (ONE - q_is_double);
        }

        // Contribution 11 point addition, x-coordinate check
        // q_elliptic * (q_sign * y1 + y3)(x2 - x1) + (x3 - x1)(y2 - q_sign * y1) = 0
        {
            Fr y1_plus_y3 = ep.y_1 + ep.y_3;
            Fr y_diff = ep.y_2 * q_sign - ep.y_1;
            Fr y_add_identity = y1_plus_y3 * x_diff + (ep.x_3 - ep.x_1) * y_diff;
            evals[12] = y_add_identity * domainSep * wire(p, WIRE.Q_ELLIPTIC) * (ONE - q_is_double);
        }

        // Contribution 10 point doubling, x-coordinate check
        // (x3 + x1 + x1) (4y1*y1) - 9 * x1 * x1 * x1 * x1 = 0
        // N.B. we're using the equivalence x1*x1*x1 === y1*y1 - curve_b to reduce degree by 1
        {
            Fr x_pow_4 = (y1_sqr + GRUMPKIN_CURVE_B_PARAMETER_NEGATED) * ep.x_1;
            Fr y1_sqr_mul_4 = y1_sqr + y1_sqr;
            y1_sqr_mul_4 = y1_sqr_mul_4 + y1_sqr_mul_4;
            Fr x1_pow_4_mul_9 = x_pow_4 * Fr.wrap(9);

            // NOTE: pushed into memory (stack >:'( )
            ep.x_double_identity = (ep.x_3 + ep.x_1 + ep.x_1) * y1_sqr_mul_4 - x1_pow_4_mul_9;

            Fr acc = ep.x_double_identity * domainSep * wire(p, WIRE.Q_ELLIPTIC) * q_is_double;
            evals[11] = evals[11] + acc;
        }

        // Contribution 11 point doubling, y-coordinate check
        // (y1 + y1) (2y1) - (3 * x1 * x1)(x1 - x3) = 0
        {
            Fr x1_sqr_mul_3 = (ep.x_1 + ep.x_1 + ep.x_1) * ep.x_1;
            Fr y_double_identity = x1_sqr_mul_3 * (ep.x_1 - ep.x_3) - (ep.y_1 + ep.y_1) * (ep.y_1 + ep.y_3);
            evals[12] = evals[12] + y_double_identity * domainSep * wire(p, WIRE.Q_ELLIPTIC) * q_is_double;
        }
    }

    // Parameters used within the Memory Relation
    // A struct is used to work around stack too deep. This relation has alot of variables
    struct MemParams {
        Fr memory_record_check;
        Fr partial_record_check;
        Fr next_gate_access_type;
        Fr record_delta;
        Fr index_delta;
        Fr adjacent_values_match_if_adjacent_indices_match;
        Fr adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation;
        Fr access_check;
        Fr next_gate_access_type_is_boolean;
        Fr ROM_consistency_check_identity;
        Fr RAM_consistency_check_identity;
        Fr timestamp_delta;
        Fr RAM_timestamp_check_identity;
        Fr memory_identity;
        Fr index_is_monotonically_increasing;
    }

    function accumulateMemoryRelation(
        Fr[NUMBER_OF_ENTITIES] memory p,
        Honk.RelationParameters memory rp,
        Fr[NUMBER_OF_SUBRELATIONS] memory evals,
        Fr domainSep
    ) internal pure {
        MemParams memory ap;

        /**
         * MEMORY
         *
         * A RAM memory record contains a tuple of the following fields:
         *  * i: `index` of memory cell being accessed
         *  * t: `timestamp` of memory cell being accessed (used for RAM, set to 0 for ROM)
         *  * v: `value` of memory cell being accessed
         *  * a: `access` type of record. read: 0 = read, 1 = write
         *  * r: `record` of memory cell. record = access + index * eta + timestamp * eta_two + value * eta_three
         *
         * A ROM memory record contains a tuple of the following fields:
         *  * i: `index` of memory cell being accessed
         *  * v: `value1` of memory cell being accessed (ROM tables can store up to 2 values per index)
         *  * v2:`value2` of memory cell being accessed (ROM tables can store up to 2 values per index)
         *  * r: `record` of memory cell. record = index * eta + value2 * eta_two + value1 * eta_three
         *
         *  When performing a read/write access, the values of i, t, v, v2, a, r are stored in the following wires +
         * selectors, depending on whether the gate is a RAM read/write or a ROM read
         *
         *  | gate type | i  | v2/t  |  v | a  | r  |
         *  | --------- | -- | ----- | -- | -- | -- |
         *  | ROM       | w1 | w2    | w3 | -- | w4 |
         *  | RAM       | w1 | w2    | w3 | qc | w4 |
         *
         * (for accesses where `index` is a circuit constant, it is assumed the circuit will apply a copy constraint on
         * `w2` to fix its value)
         *
         *
         */

        /**
         * Memory Record Check
         * Partial degree: 1
         * Total degree: 4
         *
         * A ROM/ROM access gate can be evaluated with the identity:
         *
         * qc + w1 \eta + w2 \eta_two + w3 \eta_three - w4 = 0
         *
         * For ROM gates, qc = 0
         */
        ap.memory_record_check = wire(p, WIRE.W_O) * rp.etaThree;
        ap.memory_record_check = ap.memory_record_check + (wire(p, WIRE.W_R) * rp.etaTwo);
        ap.memory_record_check = ap.memory_record_check + (wire(p, WIRE.W_L) * rp.eta);
        ap.memory_record_check = ap.memory_record_check + wire(p, WIRE.Q_C);
        ap.partial_record_check = ap.memory_record_check; // used in RAM consistency check; deg 1 or 4
        ap.memory_record_check = ap.memory_record_check - wire(p, WIRE.W_4);

        /**
         * Contribution 13 & 14
         * ROM Consistency Check
         * Partial degree: 1
         * Total degree: 4
         *
         * For every ROM read, a set equivalence check is applied between the record witnesses, and a second set of
         * records that are sorted.
         *
         * We apply the following checks for the sorted records:
         *
         * 1. w1, w2, w3 correctly map to 'index', 'v1, 'v2' for a given record value at w4
         * 2. index values for adjacent records are monotonically increasing
         * 3. if, at gate i, index_i == index_{i + 1}, then value1_i == value1_{i + 1} and value2_i == value2_{i + 1}
         *
         */
        ap.index_delta = wire(p, WIRE.W_L_SHIFT) - wire(p, WIRE.W_L);
        ap.record_delta = wire(p, WIRE.W_4_SHIFT) - wire(p, WIRE.W_4);

        ap.index_is_monotonically_increasing = ap.index_delta * ap.index_delta - ap.index_delta; // deg 2

        ap.adjacent_values_match_if_adjacent_indices_match = (ap.index_delta * MINUS_ONE + ONE) * ap.record_delta; // deg 2

        evals[14] = ap.adjacent_values_match_if_adjacent_indices_match * (wire(p, WIRE.Q_L) * wire(p, WIRE.Q_R))
            * (wire(p, WIRE.Q_MEMORY) * domainSep); // deg 5
        evals[15] = ap.index_is_monotonically_increasing * (wire(p, WIRE.Q_L) * wire(p, WIRE.Q_R))
            * (wire(p, WIRE.Q_MEMORY) * domainSep); // deg 5

        ap.ROM_consistency_check_identity = ap.memory_record_check * (wire(p, WIRE.Q_L) * wire(p, WIRE.Q_R)); // deg 3 or 7

        /**
         * Contributions 15,16,17
         * RAM Consistency Check
         *
         * The 'access' type of the record is extracted with the expression `w_4 - ap.partial_record_check`
         * (i.e. for an honest Prover `w1 * eta + w2 * eta^2 + w3 * eta^3 - w4 = access`.
         * This is validated by requiring `access` to be boolean
         *
         * For two adjacent entries in the sorted list if _both_
         *  A) index values match
         *  B) adjacent access value is 0 (i.e. next gate is a READ)
         * then
         *  C) both values must match.
         * The gate boolean check is
         * (A && B) => C  === !(A && B) || C ===  !A || !B || C
         *
         * N.B. it is the responsibility of the circuit writer to ensure that every RAM cell is initialized
         * with a WRITE operation.
         */
        Fr access_type = (wire(p, WIRE.W_4) - ap.partial_record_check); // will be 0 or 1 for honest Prover; deg 1 or 4
        ap.access_check = access_type * access_type - access_type; // check value is 0 or 1; deg 2 or 8

        // reverse order we could re-use `ap.partial_record_check`  1 -  ((w3' * eta + w2') * eta + w1') * eta
        // deg 1 or 4
        ap.next_gate_access_type = wire(p, WIRE.W_O_SHIFT) * rp.etaThree;
        ap.next_gate_access_type = ap.next_gate_access_type + (wire(p, WIRE.W_R_SHIFT) * rp.etaTwo);
        ap.next_gate_access_type = ap.next_gate_access_type + (wire(p, WIRE.W_L_SHIFT) * rp.eta);
        ap.next_gate_access_type = wire(p, WIRE.W_4_SHIFT) - ap.next_gate_access_type;

        Fr value_delta = wire(p, WIRE.W_O_SHIFT) - wire(p, WIRE.W_O);
        ap.adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
            (ap.index_delta * MINUS_ONE + ONE) * value_delta * (ap.next_gate_access_type * MINUS_ONE + ONE); // deg 3 or 6

        // We can't apply the RAM consistency check identity on the final entry in the sorted list (the wires in the
        // next gate would make the identity fail).  We need to validate that its 'access type' bool is correct. Can't
        // do  with an arithmetic gate because of the  `eta` factors. We need to check that the *next* gate's access
        // type is  correct, to cover this edge case
        // deg 2 or 4
        ap.next_gate_access_type_is_boolean =
            ap.next_gate_access_type * ap.next_gate_access_type - ap.next_gate_access_type;

        // Putting it all together...
        evals[16] = ap.adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
            * (wire(p, WIRE.Q_ARITH)) * (wire(p, WIRE.Q_MEMORY) * domainSep); // deg 5 or 8
        evals[17] =
            ap.index_is_monotonically_increasing * (wire(p, WIRE.Q_ARITH)) * (wire(p, WIRE.Q_MEMORY) * domainSep); // deg 4
        evals[18] = ap.next_gate_access_type_is_boolean * (wire(p, WIRE.Q_ARITH)) * (wire(p, WIRE.Q_MEMORY) * domainSep); // deg 4 or 6

        ap.RAM_consistency_check_identity = ap.access_check * (wire(p, WIRE.Q_ARITH)); // deg 3 or 9

        /**
         * RAM Timestamp Consistency Check
         *
         * | w1 | w2 | w3 | w4 |
         * | index | timestamp | timestamp_check | -- |
         *
         * Let delta_index = index_{i + 1} - index_{i}
         *
         * Iff delta_index == 0, timestamp_check = timestamp_{i + 1} - timestamp_i
         * Else timestamp_check = 0
         */
        ap.timestamp_delta = wire(p, WIRE.W_R_SHIFT) - wire(p, WIRE.W_R);
        ap.RAM_timestamp_check_identity = (ap.index_delta * MINUS_ONE + ONE) * ap.timestamp_delta - wire(p, WIRE.W_O); // deg 3

        /**
         * Complete Contribution 12
         * The complete RAM/ROM memory identity
         * Partial degree:
         */
        ap.memory_identity = ap.ROM_consistency_check_identity; // deg 3 or 6
        ap.memory_identity =
            ap.memory_identity + ap.RAM_timestamp_check_identity * (wire(p, WIRE.Q_4) * wire(p, WIRE.Q_L)); // deg 4
        ap.memory_identity = ap.memory_identity + ap.memory_record_check * (wire(p, WIRE.Q_M) * wire(p, WIRE.Q_L)); // deg 3 or 6
        ap.memory_identity = ap.memory_identity + ap.RAM_consistency_check_identity; // deg 3 or 9

        // (deg 3 or 9) + (deg 4) + (deg 3)
        ap.memory_identity = ap.memory_identity * (wire(p, WIRE.Q_MEMORY) * domainSep); // deg 4 or 10
        evals[13] = ap.memory_identity;
    }

    // Constants for the Non-native Field relation
    Fr constant LIMB_SIZE = Fr.wrap(uint256(1) << 68);
    Fr constant SUBLIMB_SHIFT = Fr.wrap(uint256(1) << 14);

    // Parameters used within the Non-Native Field Relation
    // A struct is used to work around stack too deep. This relation has alot of variables
    struct NnfParams {
        Fr limb_subproduct;
        Fr non_native_field_gate_1;
        Fr non_native_field_gate_2;
        Fr non_native_field_gate_3;
        Fr limb_accumulator_1;
        Fr limb_accumulator_2;
        Fr nnf_identity;
    }

    function accumulateNnfRelation(
        Fr[NUMBER_OF_ENTITIES] memory p,
        Honk.RelationParameters memory rp,
        Fr[NUMBER_OF_SUBRELATIONS] memory evals,
        Fr domainSep
    ) internal pure {
        NnfParams memory ap;

        /**
         * Contribution 12
         * Non native field arithmetic gate 2
         * deg 4
         *
         *             _                                                                               _
         *            /   _                   _                               _       14                \
         * q_2 . q_4 |   (w_1 . w_2) + (w_1 . w_2) + (w_1 . w_4 + w_2 . w_3 - w_3) . 2    - w_3 - w_4   |
         *            \_                                                                               _/
         *
         *
         */
        ap.limb_subproduct = wire(p, WIRE.W_L) * wire(p, WIRE.W_R_SHIFT) + wire(p, WIRE.W_L_SHIFT) * wire(p, WIRE.W_R);
        ap.non_native_field_gate_2 =
            (wire(p, WIRE.W_L) * wire(p, WIRE.W_4) + wire(p, WIRE.W_R) * wire(p, WIRE.W_O) - wire(p, WIRE.W_O_SHIFT));
        ap.non_native_field_gate_2 = ap.non_native_field_gate_2 * LIMB_SIZE;
        ap.non_native_field_gate_2 = ap.non_native_field_gate_2 - wire(p, WIRE.W_4_SHIFT);
        ap.non_native_field_gate_2 = ap.non_native_field_gate_2 + ap.limb_subproduct;
        ap.non_native_field_gate_2 = ap.non_native_field_gate_2 * wire(p, WIRE.Q_4);

        ap.limb_subproduct = ap.limb_subproduct * LIMB_SIZE;
        ap.limb_subproduct = ap.limb_subproduct + (wire(p, WIRE.W_L_SHIFT) * wire(p, WIRE.W_R_SHIFT));
        ap.non_native_field_gate_1 = ap.limb_subproduct;
        ap.non_native_field_gate_1 = ap.non_native_field_gate_1 - (wire(p, WIRE.W_O) + wire(p, WIRE.W_4));
        ap.non_native_field_gate_1 = ap.non_native_field_gate_1 * wire(p, WIRE.Q_O);

        ap.non_native_field_gate_3 = ap.limb_subproduct;
        ap.non_native_field_gate_3 = ap.non_native_field_gate_3 + wire(p, WIRE.W_4);
        ap.non_native_field_gate_3 = ap.non_native_field_gate_3 - (wire(p, WIRE.W_O_SHIFT) + wire(p, WIRE.W_4_SHIFT));
        ap.non_native_field_gate_3 = ap.non_native_field_gate_3 * wire(p, WIRE.Q_M);

        Fr non_native_field_identity =
            ap.non_native_field_gate_1 + ap.non_native_field_gate_2 + ap.non_native_field_gate_3;
        non_native_field_identity = non_native_field_identity * wire(p, WIRE.Q_R);

        // ((((w2' * 2^14 + w1') * 2^14 + w3) * 2^14 + w2) * 2^14 + w1 - w4) * qm
        // deg 2
        ap.limb_accumulator_1 = wire(p, WIRE.W_R_SHIFT) * SUBLIMB_SHIFT;
        ap.limb_accumulator_1 = ap.limb_accumulator_1 + wire(p, WIRE.W_L_SHIFT);
        ap.limb_accumulator_1 = ap.limb_accumulator_1 * SUBLIMB_SHIFT;
        ap.limb_accumulator_1 = ap.limb_accumulator_1 + wire(p, WIRE.W_O);
        ap.limb_accumulator_1 = ap.limb_accumulator_1 * SUBLIMB_SHIFT;
        ap.limb_accumulator_1 = ap.limb_accumulator_1 + wire(p, WIRE.W_R);
        ap.limb_accumulator_1 = ap.limb_accumulator_1 * SUBLIMB_SHIFT;
        ap.limb_accumulator_1 = ap.limb_accumulator_1 + wire(p, WIRE.W_L);
        ap.limb_accumulator_1 = ap.limb_accumulator_1 - wire(p, WIRE.W_4);
        ap.limb_accumulator_1 = ap.limb_accumulator_1 * wire(p, WIRE.Q_4);

        // ((((w3' * 2^14 + w2') * 2^14 + w1') * 2^14 + w4) * 2^14 + w3 - w4') * qm
        // deg 2
        ap.limb_accumulator_2 = wire(p, WIRE.W_O_SHIFT) * SUBLIMB_SHIFT;
        ap.limb_accumulator_2 = ap.limb_accumulator_2 + wire(p, WIRE.W_R_SHIFT);
        ap.limb_accumulator_2 = ap.limb_accumulator_2 * SUBLIMB_SHIFT;
        ap.limb_accumulator_2 = ap.limb_accumulator_2 + wire(p, WIRE.W_L_SHIFT);
        ap.limb_accumulator_2 = ap.limb_accumulator_2 * SUBLIMB_SHIFT;
        ap.limb_accumulator_2 = ap.limb_accumulator_2 + wire(p, WIRE.W_4);
        ap.limb_accumulator_2 = ap.limb_accumulator_2 * SUBLIMB_SHIFT;
        ap.limb_accumulator_2 = ap.limb_accumulator_2 + wire(p, WIRE.W_O);
        ap.limb_accumulator_2 = ap.limb_accumulator_2 - wire(p, WIRE.W_4_SHIFT);
        ap.limb_accumulator_2 = ap.limb_accumulator_2 * wire(p, WIRE.Q_M);

        Fr limb_accumulator_identity = ap.limb_accumulator_1 + ap.limb_accumulator_2;
        limb_accumulator_identity = limb_accumulator_identity * wire(p, WIRE.Q_O); //  deg 3

        ap.nnf_identity = non_native_field_identity + limb_accumulator_identity;
        ap.nnf_identity = ap.nnf_identity * (wire(p, WIRE.Q_NNF) * domainSep);
        evals[19] = ap.nnf_identity;
    }

    struct PoseidonExternalParams {
        Fr s1;
        Fr s2;
        Fr s3;
        Fr s4;
        Fr u1;
        Fr u2;
        Fr u3;
        Fr u4;
        Fr t0;
        Fr t1;
        Fr t2;
        Fr t3;
        Fr v1;
        Fr v2;
        Fr v3;
        Fr v4;
        Fr q_pos_by_scaling;
    }

    function accumulatePoseidonExternalRelation(
        Fr[NUMBER_OF_ENTITIES] memory p,
        Fr[NUMBER_OF_SUBRELATIONS] memory evals,
        Fr domainSep // i guess this is the scaling factor?
    ) internal pure {
        PoseidonExternalParams memory ep;

        ep.s1 = wire(p, WIRE.W_L) + wire(p, WIRE.Q_L);
        ep.s2 = wire(p, WIRE.W_R) + wire(p, WIRE.Q_R);
        ep.s3 = wire(p, WIRE.W_O) + wire(p, WIRE.Q_O);
        ep.s4 = wire(p, WIRE.W_4) + wire(p, WIRE.Q_4);

        ep.u1 = ep.s1 * ep.s1 * ep.s1 * ep.s1 * ep.s1;
        ep.u2 = ep.s2 * ep.s2 * ep.s2 * ep.s2 * ep.s2;
        ep.u3 = ep.s3 * ep.s3 * ep.s3 * ep.s3 * ep.s3;
        ep.u4 = ep.s4 * ep.s4 * ep.s4 * ep.s4 * ep.s4;
        // matrix mul v = M_E * u with 14 additions
        ep.t0 = ep.u1 + ep.u2; // u_1 + u_2
        ep.t1 = ep.u3 + ep.u4; // u_3 + u_4
        ep.t2 = ep.u2 + ep.u2 + ep.t1; // 2u_2
        // ep.t2 += ep.t1; // 2u_2 + u_3 + u_4
        ep.t3 = ep.u4 + ep.u4 + ep.t0; // 2u_4
        // ep.t3 += ep.t0; // u_1 + u_2 + 2u_4
        ep.v4 = ep.t1 + ep.t1;
        ep.v4 = ep.v4 + ep.v4 + ep.t3;
        // ep.v4 += ep.t3; // u_1 + u_2 + 4u_3 + 6u_4
        ep.v2 = ep.t0 + ep.t0;
        ep.v2 = ep.v2 + ep.v2 + ep.t2;
        // ep.v2 += ep.t2; // 4u_1 + 6u_2 + u_3 + u_4
        ep.v1 = ep.t3 + ep.v2; // 5u_1 + 7u_2 + u_3 + 3u_4
        ep.v3 = ep.t2 + ep.v4; // u_1 + 3u_2 + 5u_3 + 7u_4

        ep.q_pos_by_scaling = wire(p, WIRE.Q_POSEIDON2_EXTERNAL) * domainSep;
        evals[20] = evals[20] + ep.q_pos_by_scaling * (ep.v1 - wire(p, WIRE.W_L_SHIFT));

        evals[21] = evals[21] + ep.q_pos_by_scaling * (ep.v2 - wire(p, WIRE.W_R_SHIFT));

        evals[22] = evals[22] + ep.q_pos_by_scaling * (ep.v3 - wire(p, WIRE.W_O_SHIFT));

        evals[23] = evals[23] + ep.q_pos_by_scaling * (ep.v4 - wire(p, WIRE.W_4_SHIFT));
    }

    struct PoseidonInternalParams {
        Fr u1;
        Fr u2;
        Fr u3;
        Fr u4;
        Fr u_sum;
        Fr v1;
        Fr v2;
        Fr v3;
        Fr v4;
        Fr s1;
        Fr q_pos_by_scaling;
    }

    function accumulatePoseidonInternalRelation(
        Fr[NUMBER_OF_ENTITIES] memory p,
        Fr[NUMBER_OF_SUBRELATIONS] memory evals,
        Fr domainSep
    ) internal pure {
        PoseidonInternalParams memory ip;

        Fr[4] memory INTERNAL_MATRIX_DIAGONAL = [
            FrLib.from(0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7),
            FrLib.from(0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b),
            FrLib.from(0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15),
            FrLib.from(0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b)
        ];

        // add round constants
        ip.s1 = wire(p, WIRE.W_L) + wire(p, WIRE.Q_L);

        // apply s-box round
        ip.u1 = ip.s1 * ip.s1 * ip.s1 * ip.s1 * ip.s1;
        ip.u2 = wire(p, WIRE.W_R);
        ip.u3 = wire(p, WIRE.W_O);
        ip.u4 = wire(p, WIRE.W_4);

        // matrix mul with v = M_I * u 4 muls and 7 additions
        ip.u_sum = ip.u1 + ip.u2 + ip.u3 + ip.u4;

        ip.q_pos_by_scaling = wire(p, WIRE.Q_POSEIDON2_INTERNAL) * domainSep;

        ip.v1 = ip.u1 * INTERNAL_MATRIX_DIAGONAL[0] + ip.u_sum;
        evals[24] = evals[24] + ip.q_pos_by_scaling * (ip.v1 - wire(p, WIRE.W_L_SHIFT));

        ip.v2 = ip.u2 * INTERNAL_MATRIX_DIAGONAL[1] + ip.u_sum;
        evals[25] = evals[25] + ip.q_pos_by_scaling * (ip.v2 - wire(p, WIRE.W_R_SHIFT));

        ip.v3 = ip.u3 * INTERNAL_MATRIX_DIAGONAL[2] + ip.u_sum;
        evals[26] = evals[26] + ip.q_pos_by_scaling * (ip.v3 - wire(p, WIRE.W_O_SHIFT));

        ip.v4 = ip.u4 * INTERNAL_MATRIX_DIAGONAL[3] + ip.u_sum;
        evals[27] = evals[27] + ip.q_pos_by_scaling * (ip.v4 - wire(p, WIRE.W_4_SHIFT));
    }

    function scaleAndBatchSubrelations(
        Fr[NUMBER_OF_SUBRELATIONS] memory evaluations,
        Fr[NUMBER_OF_ALPHAS] memory subrelationChallenges
    ) internal pure returns (Fr accumulator) {
        accumulator = accumulator + evaluations[0];

        for (uint256 i = 1; i < NUMBER_OF_SUBRELATIONS; ++i) {
            accumulator = accumulator + evaluations[i] * subrelationChallenges[i - 1];
        }
    }
}

// Field arithmetic libraries - prevent littering the code with modmul / addmul

library CommitmentSchemeLib {
    using FrLib for Fr;

    // Avoid stack too deep
    struct ShpleminiIntermediates {
        Fr unshiftedScalar;
        Fr shiftedScalar;
        // Scalar to be multiplied by [1]₁
        Fr constantTermAccumulator;
        // Accumulator for powers of rho
        Fr batchingChallenge;
        // Linear combination of multilinear (sumcheck) evaluations and powers of rho
        Fr batchedEvaluation;
        Fr[4] denominators;
        Fr[4] batchingScalars;
        // 1/(z - r^{2^i}) for i = 0, ..., logSize, dynamically updated
        Fr posInvertedDenominator;
        // 1/(z + r^{2^i}) for i = 0, ..., logSize, dynamically updated
        Fr negInvertedDenominator;
        // ν^{2i} * 1/(z - r^{2^i})
        Fr scalingFactorPos;
        // ν^{2i+1} * 1/(z + r^{2^i})
        Fr scalingFactorNeg;
        // Fold_i(r^{2^i}) reconstructed by Verifier
        Fr[CONST_PROOF_SIZE_LOG_N] foldPosEvaluations;
    }

    function computeSquares(Fr r) internal pure returns (Fr[CONST_PROOF_SIZE_LOG_N] memory squares) {
        squares[0] = r;
        for (uint256 i = 1; i < CONST_PROOF_SIZE_LOG_N; ++i) {
            squares[i] = squares[i - 1].sqr();
        }
    }
    // Compute the evaluations Aₗ(r^{2ˡ}) for l = 0, ..., m-1

    function computeFoldPosEvaluations(
        Fr[CONST_PROOF_SIZE_LOG_N] memory sumcheckUChallenges,
        Fr batchedEvalAccumulator,
        Fr[CONST_PROOF_SIZE_LOG_N] memory geminiEvaluations,
        Fr[CONST_PROOF_SIZE_LOG_N] memory geminiEvalChallengePowers,
        uint256 logSize
    ) internal view returns (Fr[CONST_PROOF_SIZE_LOG_N] memory foldPosEvaluations) {
        for (uint256 i = CONST_PROOF_SIZE_LOG_N; i > 0; --i) {
            Fr challengePower = geminiEvalChallengePowers[i - 1];
            Fr u = sumcheckUChallenges[i - 1];

            Fr batchedEvalRoundAcc = (
                (challengePower * batchedEvalAccumulator * Fr.wrap(2))
                    - geminiEvaluations[i - 1] * (challengePower * (ONE - u) - u)
            );
            // Divide by the denominator
            batchedEvalRoundAcc = batchedEvalRoundAcc * (challengePower * (ONE - u) + u).invert();
            if (i <= logSize) {
                batchedEvalAccumulator = batchedEvalRoundAcc;
                foldPosEvaluations[i - 1] = batchedEvalRoundAcc;
            }
        }
    }
}

uint256 constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583; // EC group order. F_q

function bytes32ToString(bytes32 value) pure returns (string memory result) {
    bytes memory alphabet = "0123456789abcdef";

    bytes memory str = new bytes(66);
    str[0] = "0";
    str[1] = "x";
    for (uint256 i = 0; i < 32; i++) {
        str[2 + i * 2] = alphabet[uint8(value[i] >> 4)];
        str[3 + i * 2] = alphabet[uint8(value[i] & 0x0f)];
    }
    result = string(str);
}

// Fr utility

function bytesToFr(bytes calldata proofSection) pure returns (Fr scalar) {
    require(proofSection.length == 0x20, "invalid number of bytes to construct Fr scalar");
    scalar = FrLib.fromBytes32(bytes32(proofSection));
}

// EC Point utilities

function convertProofPoint(Honk.G1ProofPoint memory input) pure returns (Honk.G1Point memory point) {
    point = Honk.G1Point({x: input.x_0 | (input.x_1 << 136), y: input.y_0 | (input.y_1 << 136)});
}

function bytesToG1ProofPoint(bytes calldata proofSection) pure returns (Honk.G1ProofPoint memory point) {
    require(proofSection.length == 0x80, "invalid number of bytes to construct a G1 point");
    point = Honk.G1ProofPoint({
        x_0: uint256(bytes32(proofSection[0x00:0x20])),
        x_1: uint256(bytes32(proofSection[0x20:0x40])),
        y_0: uint256(bytes32(proofSection[0x40:0x60])),
        y_1: uint256(bytes32(proofSection[0x60:0x80]))
    });
}

function negateInplace(Honk.G1Point memory point) pure returns (Honk.G1Point memory) {
    point.y = (Q - point.y) % Q;
    return point;
}

function pairing(Honk.G1Point memory rhs, Honk.G1Point memory lhs) view returns (bool decodedResult) {
    bytes memory input = abi.encodePacked(
        rhs.x,
        rhs.y,
        // Fixed G2 point
        uint256(0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2),
        uint256(0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed),
        uint256(0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b),
        uint256(0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa),
        lhs.x,
        lhs.y,
        // G2 point from VK
        uint256(0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1),
        uint256(0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0),
        uint256(0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4),
        uint256(0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55)
    );

    (bool success, bytes memory result) = address(0x08).staticcall(input);
    decodedResult = success && abi.decode(result, (bool));
}

// Field arithmetic libraries - prevent littering the code with modmul / addmul




abstract contract BaseHonkVerifier is IVerifier {
    using FrLib for Fr;

    uint256 immutable $N;
    uint256 immutable $LOG_N;
    uint256 immutable $NUM_PUBLIC_INPUTS;

    constructor(uint256 _N, uint256 _logN, uint256 _numPublicInputs) {
        $N = _N;
        $LOG_N = _logN;
        $NUM_PUBLIC_INPUTS = _numPublicInputs;
    }

    // Errors
    error ProofLengthWrong();
    error PublicInputsLengthWrong();
    error SumcheckFailed();
    error ShpleminiFailed();

    // Number of field elements in a ultra honk proof, including pairing point object.
    uint256 constant PROOF_SIZE = 457;

    function loadVerificationKey() internal pure virtual returns (Honk.VerificationKey memory);

    function verify(bytes calldata proof, bytes32[] calldata publicInputs) public view override returns (bool) {
        // Check the received proof is the expected size where each field element is 32 bytes
        if (proof.length != PROOF_SIZE * 32) {
            revert ProofLengthWrong();
        }

        Honk.VerificationKey memory vk = loadVerificationKey();
        Honk.Proof memory p = TranscriptLib.loadProof(proof);
        if (publicInputs.length != vk.publicInputsSize - PAIRING_POINTS_SIZE) {
            revert PublicInputsLengthWrong();
        }

        // Generate the fiat shamir challenges for the whole protocol
        Transcript memory t = TranscriptLib.generateTranscript(
            p, publicInputs, vk.circuitSize, $NUM_PUBLIC_INPUTS, /*pubInputsOffset=*/ 1
        );

        // Derive public input delta
        t.relationParameters.publicInputsDelta = computePublicInputDelta(
            publicInputs,
            p.pairingPointObject,
            t.relationParameters.beta,
            t.relationParameters.gamma, /*pubInputsOffset=*/
            1
        );

        // Sumcheck
        bool sumcheckVerified = verifySumcheck(p, t);
        if (!sumcheckVerified) revert SumcheckFailed();

        bool shpleminiVerified = verifyShplemini(p, vk, t);
        if (!shpleminiVerified) revert ShpleminiFailed();

        return sumcheckVerified && shpleminiVerified; // Boolean condition not required - nice for vanity :)
    }

    function computePublicInputDelta(
        bytes32[] memory publicInputs,
        Fr[PAIRING_POINTS_SIZE] memory pairingPointObject,
        Fr beta,
        Fr gamma,
        uint256 offset
    ) internal view returns (Fr publicInputDelta) {
        Fr numerator = ONE;
        Fr denominator = ONE;

        Fr numeratorAcc = gamma + (beta * FrLib.from($N + offset));
        Fr denominatorAcc = gamma - (beta * FrLib.from(offset + 1));

        {
            for (uint256 i = 0; i < $NUM_PUBLIC_INPUTS - PAIRING_POINTS_SIZE; i++) {
                Fr pubInput = FrLib.fromBytes32(publicInputs[i]);

                numerator = numerator * (numeratorAcc + pubInput);
                denominator = denominator * (denominatorAcc + pubInput);

                numeratorAcc = numeratorAcc + beta;
                denominatorAcc = denominatorAcc - beta;
            }

            for (uint256 i = 0; i < PAIRING_POINTS_SIZE; i++) {
                Fr pubInput = pairingPointObject[i];

                numerator = numerator * (numeratorAcc + pubInput);
                denominator = denominator * (denominatorAcc + pubInput);

                numeratorAcc = numeratorAcc + beta;
                denominatorAcc = denominatorAcc - beta;
            }
        }

        publicInputDelta = FrLib.div(numerator, denominator);
    }

    function verifySumcheck(Honk.Proof memory proof, Transcript memory tp) internal view returns (bool verified) {
        Fr roundTarget;
        Fr powPartialEvaluation = ONE;

        // We perform sumcheck reductions over log n rounds ( the multivariate degree )
        for (uint256 round = 0; round < $LOG_N; ++round) {
            Fr[BATCHED_RELATION_PARTIAL_LENGTH] memory roundUnivariate = proof.sumcheckUnivariates[round];
            bool valid = checkSum(roundUnivariate, roundTarget);
            if (!valid) revert SumcheckFailed();

            Fr roundChallenge = tp.sumCheckUChallenges[round];

            // Update the round target for the next rounf
            roundTarget = computeNextTargetSum(roundUnivariate, roundChallenge);
            powPartialEvaluation = partiallyEvaluatePOW(tp.gateChallenges[round], powPartialEvaluation, roundChallenge);
        }

        // Last round
        Fr grandHonkRelationSum = RelationsLib.accumulateRelationEvaluations(
            proof.sumcheckEvaluations, tp.relationParameters, tp.alphas, powPartialEvaluation
        );
        verified = (grandHonkRelationSum == roundTarget);
    }

    function checkSum(Fr[BATCHED_RELATION_PARTIAL_LENGTH] memory roundUnivariate, Fr roundTarget)
        internal
        pure
        returns (bool checked)
    {
        Fr totalSum = roundUnivariate[0] + roundUnivariate[1];
        checked = totalSum == roundTarget;
    }

    // Return the new target sum for the next sumcheck round
    function computeNextTargetSum(Fr[BATCHED_RELATION_PARTIAL_LENGTH] memory roundUnivariates, Fr roundChallenge)
        internal
        view
        returns (Fr targetSum)
    {
        Fr[BATCHED_RELATION_PARTIAL_LENGTH] memory BARYCENTRIC_LAGRANGE_DENOMINATORS = [
            Fr.wrap(0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51),
            Fr.wrap(0x00000000000000000000000000000000000000000000000000000000000002d0),
            Fr.wrap(0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff11),
            Fr.wrap(0x0000000000000000000000000000000000000000000000000000000000000090),
            Fr.wrap(0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff71),
            Fr.wrap(0x00000000000000000000000000000000000000000000000000000000000000f0),
            Fr.wrap(0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31),
            Fr.wrap(0x00000000000000000000000000000000000000000000000000000000000013b0)
        ];
        // To compute the next target sum, we evaluate the given univariate at a point u (challenge).

        // Performing Barycentric evaluations
        // Compute B(x)
        Fr numeratorValue = ONE;
        for (uint256 i = 0; i < BATCHED_RELATION_PARTIAL_LENGTH; ++i) {
            numeratorValue = numeratorValue * (roundChallenge - Fr.wrap(i));
        }

        Fr[BATCHED_RELATION_PARTIAL_LENGTH] memory denominatorInverses;
        for (uint256 i = 0; i < BATCHED_RELATION_PARTIAL_LENGTH; ++i) {
            Fr inv = BARYCENTRIC_LAGRANGE_DENOMINATORS[i];
            inv = inv * (roundChallenge - Fr.wrap(i));
            inv = FrLib.invert(inv);
            denominatorInverses[i] = inv;
        }

        for (uint256 i = 0; i < BATCHED_RELATION_PARTIAL_LENGTH; ++i) {
            Fr term = roundUnivariates[i];
            term = term * denominatorInverses[i];
            targetSum = targetSum + term;
        }

        // Scale the sum by the value of B(x)
        targetSum = targetSum * numeratorValue;
    }

    // Univariate evaluation of the monomial ((1-X_l) + X_l.B_l) at the challenge point X_l=u_l
    function partiallyEvaluatePOW(Fr gateChallenge, Fr currentEvaluation, Fr roundChallenge)
        internal
        pure
        returns (Fr newEvaluation)
    {
        Fr univariateEval = ONE + (roundChallenge * (gateChallenge - ONE));
        newEvaluation = currentEvaluation * univariateEval;
    }

    function verifyShplemini(Honk.Proof memory proof, Honk.VerificationKey memory vk, Transcript memory tp)
        internal
        view
        returns (bool verified)
    {
        CommitmentSchemeLib.ShpleminiIntermediates memory mem; // stack

        // - Compute vector (r, r², ... , r²⁽ⁿ⁻¹⁾), where n = log_circuit_size
        Fr[CONST_PROOF_SIZE_LOG_N] memory powers_of_evaluation_challenge =
            CommitmentSchemeLib.computeSquares(tp.geminiR);

        // Arrays hold values that will be linearly combined for the gemini and shplonk batch openings
        Fr[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 2] memory scalars;
        Honk.G1Point[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 2] memory commitments;

        mem.posInvertedDenominator = (tp.shplonkZ - powers_of_evaluation_challenge[0]).invert();
        mem.negInvertedDenominator = (tp.shplonkZ + powers_of_evaluation_challenge[0]).invert();

        mem.unshiftedScalar = mem.posInvertedDenominator + (tp.shplonkNu * mem.negInvertedDenominator);
        mem.shiftedScalar =
            tp.geminiR.invert() * (mem.posInvertedDenominator - (tp.shplonkNu * mem.negInvertedDenominator));

        scalars[0] = ONE;
        commitments[0] = convertProofPoint(proof.shplonkQ);

        /* Batch multivariate opening claims, shifted and unshifted
        * The vector of scalars is populated as follows:
        * \f[
        * \left(
        * - \left(\frac{1}{z-r} + \nu \times \frac{1}{z+r}\right),
        * \ldots,
        * - \rho^{i+k-1} \times \left(\frac{1}{z-r} + \nu \times \frac{1}{z+r}\right),
        * - \rho^{i+k} \times \frac{1}{r} \times \left(\frac{1}{z-r} - \nu \times \frac{1}{z+r}\right),
        * \ldots,
        * - \rho^{k+m-1} \times \frac{1}{r} \times \left(\frac{1}{z-r} - \nu \times \frac{1}{z+r}\right)
        * \right)
        * \f]
        *
        * The following vector is concatenated to the vector of commitments:
        * \f[
        * f_0, \ldots, f_{m-1}, f_{\text{shift}, 0}, \ldots, f_{\text{shift}, k-1}
        * \f]
        *
        * Simultaneously, the evaluation of the multilinear polynomial
        * \f[
        * \sum \rho^i \cdot f_i + \sum \rho^{i+k} \cdot f_{\text{shift}, i}
        * \f]
        * at the challenge point \f$ (u_0,\ldots, u_{n-1}) \f$ is computed.
        *
        * This approach minimizes the number of iterations over the commitments to multilinear polynomials
        * and eliminates the need to store the powers of \f$ \rho \f$.
        */
        mem.batchingChallenge = ONE;
        mem.batchedEvaluation = ZERO;

        for (uint256 i = 1; i <= NUMBER_UNSHIFTED; ++i) {
            scalars[i] = mem.unshiftedScalar.neg() * mem.batchingChallenge;
            mem.batchedEvaluation = mem.batchedEvaluation + (proof.sumcheckEvaluations[i - 1] * mem.batchingChallenge);
            mem.batchingChallenge = mem.batchingChallenge * tp.rho;
        }
        // g commitments are accumulated at r
        for (uint256 i = NUMBER_UNSHIFTED + 1; i <= NUMBER_OF_ENTITIES; ++i) {
            scalars[i] = mem.shiftedScalar.neg() * mem.batchingChallenge;
            mem.batchedEvaluation = mem.batchedEvaluation + (proof.sumcheckEvaluations[i - 1] * mem.batchingChallenge);
            mem.batchingChallenge = mem.batchingChallenge * tp.rho;
        }

        commitments[1] = vk.qm;
        commitments[2] = vk.qc;
        commitments[3] = vk.ql;
        commitments[4] = vk.qr;
        commitments[5] = vk.qo;
        commitments[6] = vk.q4;
        commitments[7] = vk.qLookup;
        commitments[8] = vk.qArith;
        commitments[9] = vk.qDeltaRange;
        commitments[10] = vk.qElliptic;
        commitments[11] = vk.qMemory;
        commitments[12] = vk.qNnf;
        commitments[13] = vk.qPoseidon2External;
        commitments[14] = vk.qPoseidon2Internal;
        commitments[15] = vk.s1;
        commitments[16] = vk.s2;
        commitments[17] = vk.s3;
        commitments[18] = vk.s4;
        commitments[19] = vk.id1;
        commitments[20] = vk.id2;
        commitments[21] = vk.id3;
        commitments[22] = vk.id4;
        commitments[23] = vk.t1;
        commitments[24] = vk.t2;
        commitments[25] = vk.t3;
        commitments[26] = vk.t4;
        commitments[27] = vk.lagrangeFirst;
        commitments[28] = vk.lagrangeLast;

        // Accumulate proof points
        commitments[29] = convertProofPoint(proof.w1);
        commitments[30] = convertProofPoint(proof.w2);
        commitments[31] = convertProofPoint(proof.w3);
        commitments[32] = convertProofPoint(proof.w4);
        commitments[33] = convertProofPoint(proof.zPerm);
        commitments[34] = convertProofPoint(proof.lookupInverses);
        commitments[35] = convertProofPoint(proof.lookupReadCounts);
        commitments[36] = convertProofPoint(proof.lookupReadTags);

        // to be Shifted
        commitments[37] = convertProofPoint(proof.w1);
        commitments[38] = convertProofPoint(proof.w2);
        commitments[39] = convertProofPoint(proof.w3);
        commitments[40] = convertProofPoint(proof.w4);
        commitments[41] = convertProofPoint(proof.zPerm);

        /* Batch gemini claims from the prover
         * place the commitments to gemini aᵢ to the vector of commitments, compute the contributions from
         * aᵢ(−r²ⁱ) for i=1, … , n−1 to the constant term accumulator, add corresponding scalars
         *
         * 1. Moves the vector
         * \f[
         * \left( \text{com}(A_1), \text{com}(A_2), \ldots, \text{com}(A_{n-1}) \right)
         * \f]
        * to the 'commitments' vector.
        *
        * 2. Computes the scalars:
        * \f[
        * \frac{\nu^{2}}{z + r^2}, \frac{\nu^3}{z + r^4}, \ldots, \frac{\nu^{n-1}}{z + r^{2^{n-1}}}
        * \f]
        * and places them into the 'scalars' vector.
        *
        * 3. Accumulates the summands of the constant term:
         * \f[
         * \sum_{i=2}^{n-1} \frac{\nu^{i} \cdot A_i(-r^{2^i})}{z + r^{2^i}}
         * \f]
         * and adds them to the 'constant_term_accumulator'.
         */

        // Compute the evaluations Aₗ(r^{2ˡ}) for l = 0, ..., $LOG_N - 1
        Fr[CONST_PROOF_SIZE_LOG_N] memory foldPosEvaluations = CommitmentSchemeLib.computeFoldPosEvaluations(
            tp.sumCheckUChallenges,
            mem.batchedEvaluation,
            proof.geminiAEvaluations,
            powers_of_evaluation_challenge,
            $LOG_N
        );

        // Compute the Shplonk constant term contributions from A₀(±r)
        mem.constantTermAccumulator = foldPosEvaluations[0] * mem.posInvertedDenominator;
        mem.constantTermAccumulator =
            mem.constantTermAccumulator + (proof.geminiAEvaluations[0] * tp.shplonkNu * mem.negInvertedDenominator);

        mem.batchingChallenge = tp.shplonkNu.sqr();

        // Compute Shplonk constant term contributions from Aₗ(± r^{2ˡ}) for l = 1, ..., m-1;
        // Compute scalar multipliers for each fold commitment
        for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N - 1; ++i) {
            bool dummy_round = i >= ($LOG_N - 1);

            if (!dummy_round) {
                // Update inverted denominators
                mem.posInvertedDenominator = (tp.shplonkZ - powers_of_evaluation_challenge[i + 1]).invert();
                mem.negInvertedDenominator = (tp.shplonkZ + powers_of_evaluation_challenge[i + 1]).invert();

                // Compute the scalar multipliers for Aₗ(± r^{2ˡ}) and [Aₗ]
                mem.scalingFactorPos = mem.batchingChallenge * mem.posInvertedDenominator;
                mem.scalingFactorNeg = mem.batchingChallenge * tp.shplonkNu * mem.negInvertedDenominator;
                // [Aₗ] is multiplied by -v^{2l}/(z-r^{2^l}) - v^{2l+1} /(z+ r^{2^l})
                scalars[NUMBER_OF_ENTITIES + 1 + i] = mem.scalingFactorNeg.neg() + mem.scalingFactorPos.neg();

                // Accumulate the const term contribution given by
                // v^{2l} * Aₗ(r^{2ˡ}) /(z-r^{2^l}) + v^{2l+1} * Aₗ(-r^{2ˡ}) /(z+ r^{2^l})
                Fr accumContribution = mem.scalingFactorNeg * proof.geminiAEvaluations[i + 1];
                accumContribution = accumContribution + mem.scalingFactorPos * foldPosEvaluations[i + 1];
                mem.constantTermAccumulator = mem.constantTermAccumulator + accumContribution;
                // Update the running power of v
                mem.batchingChallenge = mem.batchingChallenge * tp.shplonkNu * tp.shplonkNu;
            }

            commitments[NUMBER_OF_ENTITIES + 1 + i] = convertProofPoint(proof.geminiFoldComms[i]);
        }

        // Finalise the batch opening claim
        commitments[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N] = Honk.G1Point({x: 1, y: 2});
        scalars[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N] = mem.constantTermAccumulator;

        Honk.G1Point memory quotient_commitment = convertProofPoint(proof.kzgQuotient);

        commitments[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 1] = quotient_commitment;
        scalars[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 1] = tp.shplonkZ; // evaluation challenge

        Honk.G1Point memory P_0 = batchMul(commitments, scalars);
        Honk.G1Point memory P_1 = negateInplace(quotient_commitment);

        return pairing(P_0, P_1);
    }

    function batchMul(
        Honk.G1Point[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 2] memory base,
        Fr[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 2] memory scalars
    ) internal view returns (Honk.G1Point memory result) {
        uint256 limit = NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 2;
        assembly {
            let success := 0x01
            let free := mload(0x40)

            // Write the original into the accumulator
            // Load into memory for ecMUL, leave offset for eccAdd result
            // base is an array of pointers, so we have to dereference them
            mstore(add(free, 0x40), mload(mload(base)))
            mstore(add(free, 0x60), mload(add(0x20, mload(base))))
            // Add scalar
            mstore(add(free, 0x80), mload(scalars))
            success := and(success, staticcall(gas(), 7, add(free, 0x40), 0x60, free, 0x40))

            let count := 0x01
            for {} lt(count, limit) { count := add(count, 1) } {
                // Get loop offsets
                let base_base := add(base, mul(count, 0x20))
                let scalar_base := add(scalars, mul(count, 0x20))

                mstore(add(free, 0x40), mload(mload(base_base)))
                mstore(add(free, 0x60), mload(add(0x20, mload(base_base))))
                // Add scalar
                mstore(add(free, 0x80), mload(scalar_base))

                success := and(success, staticcall(gas(), 7, add(free, 0x40), 0x60, add(free, 0x40), 0x40))
                // accumulator = accumulator + accumulator_2
                success := and(success, staticcall(gas(), 6, free, 0x80, free, 0x40))
            }

            // Return the result
            mstore(result, mload(free))
            mstore(add(result, 0x20), mload(add(free, 0x20)))
        }
    }
}

contract HonkVerifier is BaseHonkVerifier(N, LOG_N, NUMBER_OF_PUBLIC_INPUTS) {
     function loadVerificationKey() internal pure override returns (Honk.VerificationKey memory) {
       return HonkVerificationKey.loadVerificationKey();
    }
}
