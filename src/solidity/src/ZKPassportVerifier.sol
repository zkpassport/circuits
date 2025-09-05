// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {IVerifier} from "../src/OuterCount4.sol";
import {DateUtils} from "../src/DateUtils.sol";
import {StringUtils} from "../src/StringUtils.sol";
import {ArrayUtils} from "../src/ArrayUtils.sol";
import {IRootRegistry} from "../src/IRootRegistry.sol";
import {CommittedInputLen, SANCTIONS_TREES_ROOT} from "../src/Constants.sol";

enum ProofType {
  DISCLOSE,
  AGE,
  BIRTHDATE,
  EXPIRY_DATE,
  NATIONALITY_INCLUSION,
  NATIONALITY_EXCLUSION,
  ISSUING_COUNTRY_INCLUSION,
  ISSUING_COUNTRY_EXCLUSION,
  BIND,
  SANCTIONS
}

enum BoundDataIdentifier {
  NONE,
  USER_ADDRESS,
  CHAIN_ID,
  CUSTOM_DATA
}

// Add this struct to group parameters
// Suggested comment for here (I had to add this to be able to follow the contract, so it feels like a worthwhile comment):
//
// publicInputs:
// - 0: certificate_registry_root: pub Field,
// - 1: circuit_registry_root: pub Field,
// - 2: current_date: pub u64,
// - 3: service_scope: pub Field,
// - 4: service_subscope: pub Field,
// - 5:5+N: param_commitments: pub [Field; N],
// - 5+N: scoped_nullifier: pub Field,
//
// committedInputs: the preimages of the `param_commitments` of the disclosure proofs.
// committedInputCounts: offsets to locate the committedInputs of each of the param_commitments of the public_inputs.
struct ProofVerificationParams {
  bytes32 vkeyHash;
  bytes proof;
  bytes32[] publicInputs;
  bytes committedInputs;
  uint256[] committedInputCounts; // TODO: consider whether this agency (over the offsets) would enable attacks.
  // ... It might allow someone to _skip_ some of the disclosure checks, by providing an offset that jumps over them.
  // We should assert that the length of the param_commitments matches the length of the committedInputCounts. Otherwise, a user could claim `committedInputCounts`
  // is a size-1 array, when in fact it could be a size-9 array (meaning 9 disclosure proofs).
  uint256 validityPeriodInSeconds;
  string domain; // consider aligning with naming of circuits: domain -> scope, scope -> subscope. At the moment `scope` means two different things, depending on the file of code.
  string scope;
  bool devMode;
}

contract ZKPassportVerifier {
  // Constants
  // Index for the country of issuance of the passport
  uint256 constant PASSPORT_MRZ_COUNTRY_INDEX = 2;
  // Index for the three letter code of the country of citizenship
  // Note that the first three letter code (index 2) in the MRZ is the country of issuance
  // not citizenship. It is important to keep in mind for residence permits
  // where the issuing country differs from the citizenship country
  uint256 constant PASSPORT_MRZ_NATIONALITY_INDEX = 54;
  // Index for the gender of the passport holder (M, F or < if unspecified)
  uint256 constant PASSPORT_MRZ_GENDER_INDEX = 64;
  // Index for the date of expiry (YYMMDD)
  uint256 constant PASSPORT_MRZ_EXPIRY_DATE_INDEX = 65;
  // Index for the date of birth (YYMMDD) in TD1 (i.e. passport) MRZ
  uint256 constant PASSPORT_MRZ_BIRTHDATE_INDEX = 57;
  // Index for the document number in the MRZ
  uint256 constant PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX = 44;
  // Index for the document type in the MRZ
  uint256 constant PASSPORT_MRZ_DOCUMENT_TYPE_INDEX = 0;
  // Index for the name of the passport holder
  uint256 constant PASSPORT_MRZ_NAME_INDEX = 5;
  // Length of the MRZ on a passport
  uint256 constant PASSPORT_MRZ_LENGTH = 88;

  // Index for the country of issuance of the ID card
  uint256 constant ID_CARD_MRZ_COUNTRY_INDEX = 2;
  // Note that the first three letter code (index 2) in the MRZ is the country of issuance
  // not citizenship. It is important to keep in mind for residence permits
  // where the issuing country differs from the citizenship country
  uint256 constant ID_CARD_MRZ_NATIONALITY_INDEX = 45;
  // Index for the gender of the passport holder (M, F or < if unspecified)
  uint256 constant ID_CARD_MRZ_GENDER_INDEX = 37;
  // Index for the date of expiry (YYMMDD)
  uint256 constant ID_CARD_MRZ_EXPIRY_DATE_INDEX = 38;
  // Index for the date of birth (YYMMDD) in TD3 (i.e. ID cards) MRZ
  uint256 constant ID_CARD_MRZ_BIRTHDATE_INDEX = 30;
  // Index for the document number in the MRZ
  uint256 constant ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX = 5;
  // Index for the document type in the MRZ
  uint256 constant ID_CARD_MRZ_DOCUMENT_TYPE_INDEX = 0;
  // Index for the name of the passport holder
  uint256 constant ID_CARD_MRZ_NAME_INDEX = 60;
  // Length of the MRZ on an ID card
  uint256 constant ID_CARD_MRZ_LENGTH = 90;

  bytes32 public constant CERTIFICATE_REGISTRY_ID = bytes32(uint256(1));
  bytes32 public constant CIRCUIT_REGISTRY_ID = bytes32(uint256(2));
  bytes32 public constant SANCTIONS_REGISTRY_ID = bytes32(uint256(3));

  address public admin;
  bool public paused;

  // Which vkhashes are these? vkhashes of outer circuits? Please comment storage variables.
  mapping(bytes32 => address) public vkeyHashToVerifier;

  // Maybe make this immutable as this should most likely not change
  IRootRegistry public rootRegistry;

  // Events
  event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
  event PausedStatusChanged(bool paused);
  event ZKPassportVerifierDeployed(address indexed admin, uint256 timestamp);
  event VerifierAdded(bytes32 indexed vkeyHash, address indexed verifier);
  event VerifierRemoved(bytes32 indexed vkeyHash);
  event CertificateRegistryRootAdded(bytes32 indexed certificateRegistryRoot);
  event CertificateRegistryRootRemoved(bytes32 indexed certificateRegistryRoot);
  event SanctionsTreesRootUpdates(bytes32 indexed _sanctionsTreesRoot);

  /**
   * @dev Constructor
   */
  constructor(address _rootRegistry) {
    require(_rootRegistry != address(0), "Root registry cannot be zero address");
    admin = msg.sender;
    rootRegistry = IRootRegistry(_rootRegistry);
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

  function addVerifiers(
    bytes32[] calldata vkeyHashes,
    address[] calldata verifiers
  ) external onlyAdmin {
    for (uint256 i = 0; i < vkeyHashes.length; i++) {
      vkeyHashToVerifier[vkeyHashes[i]] = verifiers[i];
      emit VerifierAdded(vkeyHashes[i], verifiers[i]);
    }
  }

  function removeVerifiers(bytes32[] calldata vkeyHashes) external onlyAdmin {
    for (uint256 i = 0; i < vkeyHashes.length; i++) {
      delete vkeyHashToVerifier[vkeyHashes[i]];
      emit VerifierRemoved(vkeyHashes[i]);
    }
  }

  function updateRootRegistry(address _rootRegistry) external onlyAdmin {
    require(_rootRegistry != address(0), "Root registry cannot be zero address");
    rootRegistry = IRootRegistry(_rootRegistry);
  }

  // Visually inspected.
  function checkDate(
    bytes32[] memory publicInputs,
    uint256 validityPeriodInSeconds
  ) internal view returns (bool) {
    uint256 currentDateTimeStamp = uint256(publicInputs[2]);
    return DateUtils.isDateValid(currentDateTimeStamp, validityPeriodInSeconds);
  }

  // Visually inspected.
  function getDisclosedData(
    bytes calldata discloseBytes,
    bool isIDCard
  )
    public
    pure
    returns (
      string memory name,
      string memory issuingCountry,
      string memory nationality,
      string memory gender,
      string memory birthDate,
      string memory expiryDate,
      string memory documentNumber,
      string memory documentType
    )
  {
    // Recommendation: create globals to replace all of these magic numbers (as per the circuits).
    if (!isIDCard) {
      name = string(discloseBytes[PASSPORT_MRZ_NAME_INDEX:PASSPORT_MRZ_NAME_INDEX + 39]);
      issuingCountry = string(
        discloseBytes[PASSPORT_MRZ_COUNTRY_INDEX:PASSPORT_MRZ_COUNTRY_INDEX + 3]
      );
      nationality = string(
        discloseBytes[PASSPORT_MRZ_NATIONALITY_INDEX:PASSPORT_MRZ_NATIONALITY_INDEX + 3]
      );
      gender = string(discloseBytes[PASSPORT_MRZ_GENDER_INDEX:PASSPORT_MRZ_GENDER_INDEX + 1]);
      birthDate = string(
        discloseBytes[PASSPORT_MRZ_BIRTHDATE_INDEX:PASSPORT_MRZ_BIRTHDATE_INDEX + 6]
      );
      expiryDate = string(
        discloseBytes[PASSPORT_MRZ_EXPIRY_DATE_INDEX:PASSPORT_MRZ_EXPIRY_DATE_INDEX + 6]
      );
      documentNumber = string(
        discloseBytes[PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX:PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX + 9]
      );
      documentType = string(
        discloseBytes[PASSPORT_MRZ_DOCUMENT_TYPE_INDEX:PASSPORT_MRZ_DOCUMENT_TYPE_INDEX + 2]
      );
    } else {
      name = string(discloseBytes[ID_CARD_MRZ_NAME_INDEX:ID_CARD_MRZ_NAME_INDEX + 30]);
      issuingCountry = string(
        discloseBytes[ID_CARD_MRZ_COUNTRY_INDEX:ID_CARD_MRZ_COUNTRY_INDEX + 3]
      );
      nationality = string(
        discloseBytes[ID_CARD_MRZ_NATIONALITY_INDEX:ID_CARD_MRZ_NATIONALITY_INDEX + 3]
      );
      gender = string(discloseBytes[ID_CARD_MRZ_GENDER_INDEX:ID_CARD_MRZ_GENDER_INDEX + 1]);
      birthDate = string(
        discloseBytes[ID_CARD_MRZ_BIRTHDATE_INDEX:ID_CARD_MRZ_BIRTHDATE_INDEX + 6]
      );
      expiryDate = string(
        discloseBytes[ID_CARD_MRZ_EXPIRY_DATE_INDEX:ID_CARD_MRZ_EXPIRY_DATE_INDEX + 6]
      );
      documentNumber = string(
        discloseBytes[ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX:ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX + 9]
      );
      documentType = string(
        discloseBytes[ID_CARD_MRZ_DOCUMENT_TYPE_INDEX:ID_CARD_MRZ_DOCUMENT_TYPE_INDEX + 2]
      );
    }
  }

  // Visually inspected.
  // Possibly-critical bug (as mentioned in the corresponding circuit):
  // Neither the circuits nor this contract are enforcing that each `discloseMask` byte is 
  // actually a bit (0 or 1 only). If the mask is not properly enforced by the verifier,
  // then a user could mutate the details of their passport, using the mask, to lie about their
  // passport details. E.g. they could multiply any disclosed byte by 2 -- e.g. to shift which
  // country they're from.
  // This arguably places quite a high mental burden on the app developer, who must write
  // a smart contract which enacts these missing checks. 
  // Slightly cheekily, I should point out that even the example SampleContract.sol is neglecting
  // to check the `discloseMask`; it is throwing away that data. So that means a malicious user
  // could indeed trick the SampleContract into thinking they're from a different country, by
  // cleverly choosing the `disclose_mask` inputs to their "disclosure" circuit. Or they could
  // mutate their date of birth. They could mutate anything.
  // Yay!!! Dopamine for me as an auditor!
  //
  // I suspect an app developer might blindly follow the patterns in SampleConrtact.sol, and 
  // so it's very possible that an app developer could fall afoul of this bug.
  function getDiscloseProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (bytes memory discloseMask, bytes memory discloseBytes) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Disclose circuits have 181 bytes of committed inputs
      // The first byte is the proof type, so we search for that.
      if (committedInputCounts[i] == CommittedInputLen.DISCLOSE_BYTES) {
        // This only works because `181` is unique in the CommittedInputLen's. If it wasn't unique,
        // this `require` would throw an error if we encountered another ProofType with `181` bytes.
        // It's something to be aware of, in case the number of bytes ever changes with refactors. Indeed,
        // there _are_ some proof types which have matching CommittedInputLen's.
        // Consider instead something like:
        // ```
        // if (
        //     committedInputCounts[i] == CommittedInputLen.DISCLOSE_BYTES &&
        //     committedInputs[offset] == bytes1(uint8(ProofType.DISCLOSE)
        // ) {
        // ```
        // ^^^ this would also be consistent with some other `get...ProofInputs` functions in this file.
        require(committedInputs[offset] == bytes1(uint8(ProofType.DISCLOSE)), "Invalid proof type");
        discloseMask = committedInputs[offset + 1:offset + 91]; // Replace 91 and 181 with global constants.
        discloseBytes = committedInputs[offset + 91:offset + 181];
        // Concern: is it possible to chain multiple "DISCLOSE" proof types into a single Outer proof?
        // I don't think I've seen anything which ensures that each `ProofType` can only be used at most once.
        // Consider asserting that each ProofType can only be used once, within the Outer circuit (unless
        // I'm overlooking a use case that would require multiple of one ProofType?).
        // My concern came from me thinking that this `for` loop should `break;` once it finds a match,
        // to save gas. And then I wondered what would happen if there were two `DISCLOSE` proofs
        // within this Outer proof: it would mean we'd never be able to extract the _first_ occurrence,
        // because the loop would carry on and overwrite the output `discloseBytes` with the _second_
        // occurrence.
        // This concern is probably valid for all `get...ProofInputs` functions in this file (this is the
        // first one that I've looked at).
        // Consider adding `break;` here, to save some gas.
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Disclose proof inputs not found");
  }

  // Which kinds of proof is this actually for, in all?
  // compare/expiry?
  // Also compare/birthdate? It's not clear because of the hard-coded COMPARE_EXPIRY name below. COMPARE_BIRTHDATE doesn't appear in this file.
  // Consider instead:
  // `if ( (committedInputCounts[i] == CommittedInputLen.COMPARE_EXPIRY) || (committedInputCounts[i] == CommittedInputLen.COMPARE_BIRTHDAY) ) && ...`
  // Or: remove `COMPARE_BIRTHDATE` and rename to `COMPARE_EXPIRY` to `COMPARE_DATE` with a comment to say that this covers BIRTHDATE and EXPIRY DATE use cases.
  // Also consider renaming this function to getCompareDateProofInputs or something that makes it clear that it's the "compare" flow.
  function getDateProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts,
    ProofType proofType
  ) public pure returns (uint256 currentDate, uint256 minDate, uint256 maxDate) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Date circuits have 25 bytes of committed inputs
      // The first byte is the proof type
      if (
        committedInputCounts[i] == CommittedInputLen.COMPARE_EXPIRY &&
        committedInputs[offset] == bytes1(uint8(proofType))
      ) {
        // Get rid of the padding 0s bytes as the timestamp is contained within the first 64 bits
        // i.e. 256 - 64 = 192
        currentDate = uint256(bytes32(committedInputs[offset + 1:offset + 9])) >> 192;
        minDate = uint256(bytes32(committedInputs[offset + 9:offset + 17])) >> 192;
        maxDate = uint256(bytes32(committedInputs[offset + 17:offset + 25])) >> 192;
        // See concern of the getDiscloseProofInputs fn above, relating to multiple of the same ProofType being used in a single Outer circuit.
        // Also consider `break;` here, once found.
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Date proof inputs not found");
  }

  function getAgeProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (uint256 currentDate, uint8 minAge, uint8 maxAge) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // The age circuit has 11 bytes of committed inputs
      // The first byte is the proof type
      // This only works because `11` is unique in the CommittedInputLen's. If it wasn't unique,
      // this `require` would throw an error if we encountered another ProofType with `11` bytes.
      // It's something to be aware of, in case the number of bytes ever changes with refactors. Indeed,
      // there _are_ some proof types which have matching CommittedInputLen's.
      // Consider instead something like:
      // ```
      // if (
      //     committedInputCounts[i] == CommittedInputLen.COMPARE_AGE &&
      //     committedInputs[offset] == bytes1(uint8(ProofType.AGE)
      // ) {
      // ```
      // (^^^ this pattern is followed in some of the other fns in this file)
      if (committedInputCounts[i] == CommittedInputLen.COMPARE_AGE) {
        require(committedInputs[offset] == bytes1(uint8(ProofType.AGE)), "Invalid proof type");
        // Get rid of the padding 0s bytes as the timestamp is contained within the first 64 bits
        // i.e. 256 - 64 = 192
        currentDate = uint256(bytes32(committedInputs[offset + 1:offset + 9])) >> 192;
        minAge = uint8(committedInputs[offset + 9]);
        maxAge = uint8(committedInputs[offset + 10]);
        // See concern of the getDiscloseProofInputs fn above, relating to multiple of the same ProofType being used in a single Outer circuit.
        // Also consider `break;` here, once found.
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Age proof inputs not found");
  }

  // Recommendation: add a doc comment to say which circuits this covers. I think:
  // INCL_ISSUING_COUNTRY, EXCL_ISSUING_COUNTRY, INCL_NATIONALITY, EXCL_NATIONALITY
  function getCountryProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts,
    ProofType proofType
  ) public pure returns (string[] memory countryList) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Country (inclusion and exclusion) circuits have 601 bytes of committed inputs
      // The first byte is the proof type
      if (
        committedInputCounts[i] == CommittedInputLen.INCL_NATIONALITY &&
        committedInputs[offset] == bytes1(uint8(proofType))
      ) {
        // Consider using a global instead of the magic number 200.
        countryList = new string[](200);
        for (uint256 j = 0; j < 200; j++) {
          // Each country code is 3 bytes long.
          // `+ 1` skips over the proofType byte at the start.
          // Consider doing `offset += 1;` before this loop begins, instead of `+ 1` in every iteration in the line below.
          // Consider also assigning: `offset += j * 3` each loop, to save some gas.
          if (committedInputs[offset + j * 3 + 1] == 0) {
            // The circuit constrains that once we've reached the first `0`,
            // we won't encounter any further nonzero values.
            // We don't need to include the padding bytes
            break;
          }
          countryList[j] = string(committedInputs[offset + j * 3 + 1:offset + j * 3 + 3 + 1]);
        }
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Country proof inputs not found");
  }

  function getBindProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (bytes memory data) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // The bind data circuit has 501 bytes of committed inputs
      // The first byte is the proof type
      // See concern of the getDiscloseProofInputs fn above, relating to multiple of the same ProofType being used in a single Outer circuit.
      //
      // Also:
      // This only works because `501` is unique in the CommittedInputLen's. If it wasn't unique,
      // this `require` would throw an error if we encountered another ProofType with `501` bytes.
      // It's something to be aware of, in case the number of bytes ever changes with refactors. Indeed,
      // there _are_ some proof types which have matching CommittedInputLen's.
      // Consider instead something like:
      // ```
      // if (
      //     committedInputCounts[i] == CommittedInputLen.BIND &&
      //     committedInputs[offset] == bytes1(uint8(ProofType.BIND)
      // ) {
      // ```
      // (^^^ this pattern is followed in some of the other fns in this file)
      if (committedInputCounts[i] == CommittedInputLen.BIND) {
        require(committedInputs[offset] == bytes1(uint8(ProofType.BIND)), "Invalid proof type");
        // Get the length of the data from the tag length encoded in the data
        // The developer should check on their side the actual data returned before
        // the padding bytes by asserting the values returned from getBoundData meets
        // what they expect
        // This `while` loop seems like quite a complex preamble just to check for zero padding at the
        // end of the bytes. Especially since the logic of this `while` loop is effectively repeated in `getBoundData`.
        // You could perhaps instead assert padding within `getBoundData`, after its `while` loop.
        uint256 dataLength = 0;
        while (dataLength < 500) {
          // Consider `offset += 1` before we enter this loop, to remove all the below `+ 1`'s.
          //
          // Each `if` statement in this loop would benefit from a comment explaining the layout
          // of the bytes. It's not clear to me (having come here from all the circuits, which
          // don't assume any layout structure for these 500 bytes).
          if (
            committedInputs[offset + 1 + dataLength] ==
            bytes1(uint8(BoundDataIdentifier.USER_ADDRESS))
          ) {
            // It makes me nervous that we're not checking the claimed lengths against known constants.
            // E.g. we know an address should be 20 bytes, but that's not being asserted here.
            // E.g. we know a chainId should be of a certain length (2 bytes?), but that's not being asserted here.
            // I'm worried about an attack where a user could provide an incorrect addressLength or chainIdLength,
            // which the code below would blindly accept and just jump over that many bytes. Perhaps it
            // would allow a user to somehow skip over some bytes to avoid being bound to those bytes.
            // Oh, it's being checked in getBoundData
            //
            // Looks like each length is encoded as 2 bytes? That makes sense, since 1 byte only encodes up to 256, but the array is 500 long.
            uint16 addressLength = uint16(
              bytes2(committedInputs[offset + 1 + dataLength + 1:offset + 1 + dataLength + 3])
            );
            // Consider something like:
            // dataLength += 1 /* BoundDataIdentifier */ + 2 /* length bytes */ + addressLength; // for readability.
            dataLength += 2 + addressLength + 1;
          } else if (
            committedInputs[offset + 1 + dataLength] == bytes1(uint8(BoundDataIdentifier.CHAIN_ID))
          ) {
            uint16 chainIdLength = uint16(
              bytes2(committedInputs[offset + 1 + dataLength + 1:offset + 1 + dataLength + 3])
            );
            dataLength += 2 + chainIdLength + 1;
          } else if (
            committedInputs[offset + 1 + dataLength] ==
            bytes1(uint8(BoundDataIdentifier.CUSTOM_DATA))
          ) {
            uint16 customDataLength = uint16(
              bytes2(committedInputs[offset + 1 + dataLength + 1:offset + 1 + dataLength + 3])
            );
            dataLength += 2 + customDataLength + 1;
          } else {
            break;
          }
        }
        require(dataLength > 0 && dataLength <= 500, "Invalid data length");

        // Verify all padding bytes are zeros
        for (uint256 j = dataLength; j < 500; j++) {
          require(committedInputs[offset + 1 + j] == 0, "Invalid padding");
        }

        data = committedInputs[offset + 1:offset + 501];
        // See concern of the getDiscloseProofInputs fn above, relating to multiple of the same ProofType being used in a single Outer circuit.
        // Also consider `break;` here, once found, to save gas.
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Bind data proof inputs not found");
  }

  function getSanctionsProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (bytes32 sanctionsTreesCommitment) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; ++i) {
      // See concern of the getDiscloseProofInputs fn above, relating to multiple of the same ProofType being used in a single Outer circuit.
      //
      // Also:
      // This only works because `501` is unique in the CommittedInputLen's. If it wasn't unique,
      // this `require` would throw an error if we encountered another ProofType with `501` bytes.
      // It's something to be aware of, in case the number of bytes ever changes with refactors. Indeed,
      // there _are_ some proof types which have matching CommittedInputLen's.
      // Consider instead something like:
      // ```
      // if (
      //     committedInputCounts[i] == CommittedInputLen.BIND &&
      //     committedInputs[offset] == bytes1(uint8(ProofType.BIND)
      // ) {
      // ```
      // (^^^ this pattern is followed in some of the other fns in this file)
      if (committedInputCounts[i] == CommittedInputLen.SANCTIONS) {
        require(
          committedInputs[offset] == bytes1(uint8(ProofType.SANCTIONS)),
          "Invalid proof type"
        );

        sanctionsTreesCommitment = bytes32(committedInputs[offset + 1:offset + 33]);
        // Consider `break;` here, once found, to save gas.
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Sanctions proof inputs not found");
  }

  function enforceSanctionsRoot(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public view {
    bytes32 proofSanctionsRoot = getSanctionsProofInputs(committedInputs, committedInputCounts);
    _validateSanctionsRoot(proofSanctionsRoot);
  }

  // Consider moving this function up to be directly below the `getBindProofInputs` fn.
  function getBoundData(
    bytes calldata data
  ) public pure returns (address senderAddress, uint256 chainId, string memory customData) {
    uint256 offset = 0;
    while (offset < 500) {
      if (data[offset] == bytes1(uint8(BoundDataIdentifier.USER_ADDRESS))) {
        uint16 addressLength = uint16(bytes2(data[offset + 1:offset + 3]));
        senderAddress = address(bytes20(data[offset + 3:offset + 3 + addressLength]));
        offset += 2 + addressLength + 1;
      } else if (data[offset] == bytes1(uint8(BoundDataIdentifier.CHAIN_ID))) {
        uint16 chainIdLength = uint16(bytes2(data[offset + 1:offset + 3]));
        require(chainIdLength <= 32, "Chain id length too long");
        // bytes32 right pads while we want to left pad
        // so we shift the bytes to the right by 256 - (chainIdLength * 8)
        chainId = uint256(
          bytes32(data[offset + 3:offset + 3 + chainIdLength]) >> (256 - (chainIdLength * 8))
        );
        offset += 2 + chainIdLength + 1;
      } else if (data[offset] == bytes1(uint8(BoundDataIdentifier.CUSTOM_DATA))) {
        uint16 customDataLength = uint16(bytes2(data[offset + 1:offset + 3]));
        customData = string(data[offset + 3:offset + 3 + customDataLength]);
        offset += 2 + customDataLength + 1;
      } else {
        break;
      }
    }
  }

  // Visually inspected.
  // Missing tests.
  function verifyScopes(
    bytes32[] calldata publicInputs,
    string calldata domain,
    string calldata scope
  ) public pure returns (bool) {
    // One byte is dropped at the end
    // What we call scope internally is derived from the domain
    bytes32 scopeHash = StringUtils.isEmpty(domain)
      ? bytes32(0)
      : sha256(abi.encodePacked(domain)) >> 8;
    // What we call the subscope internally is the scope specified
    // manually in the SDK
    bytes32 subscopeHash = StringUtils.isEmpty(scope)
      ? bytes32(0)
      : sha256(abi.encodePacked(scope)) >> 8;
    return publicInputs[3] == scopeHash && publicInputs[4] == subscopeHash;
  }

  function verifyCommittedInputs(
    bytes32[] memory paramCommitments,
    bytes calldata committedInputs,
    uint256[] memory committedInputCounts
  ) internal pure {
    uint256 offset = 0;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // One byte is dropped inside the circuit as BN254 is limited to 254 bits
      bytes32 calculatedCommitment = sha256(
        abi.encodePacked(committedInputs[offset:offset + committedInputCounts[i]])
      ) >> 8;
      require(calculatedCommitment == paramCommitments[i], "Invalid commitment");
      offset += committedInputCounts[i];
    }

    // Missing check:
    // assert(committedInputs.length == offset); // to ensure there are no extra bytes of committedInputs, to avoid unexpected behaviour.
  }

  function _getVerifier(bytes32 vkeyHash) internal view returns (address) {
    address verifier = vkeyHashToVerifier[vkeyHash];
    require(verifier != address(0), "Verifier not found");
    return verifier;
  }

  function _validateCertificateRoot(bytes32 certificateRoot) internal view {
    require(
      rootRegistry.isRootValid(CERTIFICATE_REGISTRY_ID, certificateRoot),
      "Invalid certificate registry root"
    );
  }

  function _validateCircuitRoot(bytes32 circuitRoot) internal view {
    require(
      rootRegistry.isRootValid(CIRCUIT_REGISTRY_ID, circuitRoot),
      "Invalid circuit registry root"
    );
  }

  function _validateSanctionsRoot(bytes32 sanctionsRoot) internal view {
    require(
      rootRegistry.isRootValid(SANCTIONS_REGISTRY_ID, sanctionsRoot),
      "Invalid sanctions registry root"
    );
  }

  // MAIN
  /**
   * @notice Verifies a proof from ZKPassport
   *
   * WARNING: the outputs of the disclosure proofs are not checked by this function. You will need
   * to validate those inputs in your own smart contract (see SampleContract.sol for an example).
   *
   * @param params The proof verification parameters
   * @return isValid True if the proof is valid, false otherwise
   * @return uniqueIdentifier The unique identifier associated to the identity document that generated the proof
   */
  function verifyProof(
    ProofVerificationParams calldata params
  ) external view whenNotPaused returns (bool, bytes32) { // consider naming the return values, for readability.
    address verifier = _getVerifier(params.vkeyHash);

    // Validate certificate registry root
    // Consider introducing globals for the indices of the publicInputs, to avoid mistakes.
    // I.e.:
    // uint256 CERTIFICATE_REGISTRY_ROOT_INDEX = 0;
    // ...
    //
    // You wouldn't be able to do it for the scoped_nullifier, though, because it's at a fiddly position 
    // after the dynamic array of param_commitments.
    _validateCertificateRoot(params.publicInputs[0]);

    // Validate circuit registry root
    _validateCircuitRoot(params.publicInputs[1]);

    // Checks the date of the proof
    require(
      checkDate(params.publicInputs, params.validityPeriodInSeconds),
      "Proof expired or date is invalid"
    );

    // Validate scopes if provided
    require(verifyScopes(params.publicInputs, params.domain, params.scope), "Invalid scopes");

    // Verifies the commitments against the committed inputs
    // Possibly critical bug: The user can provide `committedInputCounts = []` (for example),
    // to skip over _all_ of the param_commitments, meaning none of their preimages would be checked.
    // To fix (in pseudocode):
    // ```
    // let NUM_PUBLIC_INPUT_FIELDS = 7; // certificate_registry_root, circuit_registry_root, current_date, service_scope, service_subscope, param_commitments, scoped_nullifier.
    // assert(params.publicInputs.length == NUM_PUBLIC_INPUT_FIELDS); // just because.
    // let num_param_commitments = params.publicInputs.length - NUM_PUBLIC_INPUT_FIELDS + 1;
    // assert(params.committedInputCounts.length == num_param_commitments); // this is the critical check that's missing.
    // ```
    //
    // Consider:
    // let scoped_nullifier_index = params.publicInputs.length - 1;
    // let scoped_nullifier = params.publicInputs[scoped_nullifier_index];
    // ... and using that thereafter, for clarity.
    verifyCommittedInputs(
      // Extracts the commitments from the public inputs
      params.publicInputs[5:params.publicInputs.length - 1],
      params.committedInputs,
      params.committedInputCounts
    );

    // Allow mock proofs in dev mode
    // Mock proofs are recognisable by their unique identifier set to 1
    require(
      params.publicInputs[params.publicInputs.length - 1] != bytes32(uint256(1)) || params.devMode,
      "Mock proofs are only allowed in dev mode"
    );

    return (
      IVerifier(verifier).verify(params.proof, params.publicInputs),
      params.publicInputs[params.publicInputs.length - 1]
    );
  }
}
