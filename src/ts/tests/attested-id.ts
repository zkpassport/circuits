import { p256, p384 } from "@noble/curves/nist.js"
import { sha256, sha384 } from "@noble/hashes/sha2.js"
import {
  hashSaltDg1Dg2HashPrivateNullifier,
  normalizeDg2Hash,
  packBeBytesIntoFields,
  packLeBytesAndHashPoseidon2,
  Binary,
} from "@zkpassport/utils"
import { poseidon2HashAsync } from "@zkpassport/poseidon2"

// Synthetic App Attest (iOS) and key attestation + Play Integrity (Android) inputs for the
// attested_id circuits. The root keys are circuit inputs, so a self-made chain proves.

export const DG1_LENGTH = 95
export const CLIENT_DATA_MAX_LEN = 169
const AUTH_DATA_MAX_LEN = 180
const CREDENTIAL_TBS_MAX_LEN = 1000
const APP_ID_MAX_LEN = 100
const INTEGRITY_TOKEN_MAX_LENGTH = 1024
const ATTESTATION_KEY_TYPE_APPLE = 1
const ATTESTATION_KEY_TYPE_GOOGLE = 2
const PROOF_TYPE_ATTESTED_ID = 11n
const SHA256_IDENTIFIER = 3

export const FACEMATCH_MODE_REGULAR = 1
export const FACEMATCH_MODE_STRICT = 2

const enc = (s: string) => new TextEncoder().encode(s)
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}
const pad = (bytes: Uint8Array, len: number) => {
  if (bytes.length > len) throw new Error(`${bytes.length} bytes exceed ${len}`)
  return Array.from(concat(bytes, new Uint8Array(len - bytes.length)))
}

function derLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len])
  const bytes: number[] = []
  for (let l = len; l > 0; l >>= 8) bytes.unshift(l & 0xff)
  return new Uint8Array([0x80 | bytes.length, ...bytes])
}
const tlv = (tag: number | number[], ...content: Uint8Array[]) => {
  const body = concat(...content)
  return concat(new Uint8Array(Array.isArray(tag) ? tag : [tag]), derLength(body.length), body)
}
const seq = (...c: Uint8Array[]) => tlv(0x30, ...c)
const set = (...c: Uint8Array[]) => tlv(0x31, ...c)
const octets = (...c: Uint8Array[]) => tlv(0x04, ...c)
const int = (n: number) => tlv(0x02, new Uint8Array(n < 0x80 ? [n] : [n >> 8, n & 0xff]))
const enumerated = (n: number) => tlv(0x0a, new Uint8Array([n]))
const utf8 = (s: string) => tlv(0x0c, enc(s))
const oid = (hex: string) => tlv(0x06, Buffer.from(hex, "hex"))

const OID_EC_PUBLIC_KEY = "2a8648ce3d0201"
const OID_P256 = "2a8648ce3d030107"
const OID_P384 = "2b81040022"
const OID_ECDSA_SHA256 = "2a8648ce3d040302"
const OID_ECDSA_SHA384 = "2a8648ce3d040303"
const OID_SHA256 = "608648016503040201"
const OID_COMMON_NAME = "550403"
const OID_APPLE_NONCE = "2a864886f763640802"
const OID_APPLE_APP_ID = "2a864886f763640805"
const OID_ANDROID_KEY_ATTESTATION = "2b06010401d679020111"

type Curve = typeof p256 | typeof p384

class Key {
  readonly publicKey: Uint8Array
  constructor(
    readonly curve: Curve,
    private readonly secretKey: Uint8Array,
  ) {
    this.publicKey = curve.getPublicKey(secretKey, false).subarray(1)
  }
  static p384(label: string) {
    return new Key(p384, sha384(enc(label)))
  }
  static p256(label: string) {
    return new Key(p256, sha256(enc(label)))
  }
  sign(msgHash: Uint8Array): Uint8Array {
    return this.curve.sign(msgHash, this.secretKey, { prehash: false })
  }
  get curveOid() {
    return this.curve === p384 ? OID_P384 : OID_P256
  }
}

const name = (cn: string) => seq(set(seq(oid(OID_COMMON_NAME), utf8(cn))))

function tbsCertificate(opts: {
  issuer: string
  subject: string
  signatureOid: string
  subjectKey: Key
  extensions?: Uint8Array[]
}): Uint8Array {
  const spki = seq(
    seq(oid(OID_EC_PUBLIC_KEY), oid(opts.subjectKey.curveOid)),
    tlv(0x03, new Uint8Array([0x00, 0x04]), opts.subjectKey.publicKey),
  )
  return seq(
    tlv(0xa0, int(2)),
    int(0x1234),
    seq(oid(opts.signatureOid)),
    name(opts.issuer),
    seq(tlv(0x17, enc("250101000000Z")), tlv(0x17, enc("350101000000Z"))),
    name(opts.subject),
    spki,
    ...(opts.extensions ? [tlv(0xa3, seq(...opts.extensions))] : []),
  )
}

const extension = (extnOid: string, value: Uint8Array) => seq(oid(extnOid), octets(value))

/** ZKPassportAppAttest client data, as the facematch lib parses it */
export function buildClientData(opts: {
  mode: number
  digest: Uint8Array
  digestAlgorithmOid?: string
}): Uint8Array {
  const digestInfo = seq(seq(oid(opts.digestAlgorithmOid ?? OID_SHA256)), octets(opts.digest))
  const faceMatch = seq(
    enumerated(opts.mode),
    digestInfo,
    octets(sha256(enc("face match result"))),
    int(0),
    int(0),
  )
  return seq(int(1), utf8("1.0.0"), enumerated(1), tlv(0xa1, faceMatch))
}

/** The client data hash both platforms bind: the packed Poseidon2 hash, as 32 BE bytes */
export async function getClientDataHash(clientData: Uint8Array): Promise<Uint8Array> {
  const hash = await packLeBytesAndHashPoseidon2(clientData)
  return Buffer.from(hash.toString(16).padStart(64, "0"), "hex")
}

export function padDg1(dg1: Uint8Array): Uint8Array {
  return new Uint8Array(pad(dg1, DG1_LENGTH))
}

export function calculateAttestedDigest(dg1: Uint8Array, portraitHash: Uint8Array): Uint8Array {
  return sha256(concat(padDg1(dg1), portraitHash))
}

function mrzLayout(dg1: Uint8Array) {
  const isIdCard = dg1[93] !== 0 && dg1[94] !== 0
  return isIdCard
    ? { documentNumber: 5, dateOfBirth: 30, expiryDate: 38 }
    : { documentNumber: 44, dateOfBirth: 57, expiryDate: 65 }
}

export function getExpiryDate(dg1: Uint8Array): number[] {
  const padded = padDg1(dg1)
  const start = 5 + mrzLayout(padded).expiryDate
  return Array.from(padded.subarray(start, start + 6))
}

// The whole document number: a TD1 number longer than 9 characters continues in the optional data
function getFullDocumentNumber(padded: Uint8Array): Uint8Array {
  const mrz = padded.subarray(5)
  const start = mrzLayout(padded).documentNumber
  const number = new Uint8Array(24).fill(60)
  number.set(mrz.subarray(start, start + 9))
  if (padded[93] !== 0 && padded[94] !== 0 && mrz[14] === 60) {
    number.set(mrz.subarray(15, 30), 9)
  }
  return number
}

export async function calculateTier2PrivateNullifier(dg1: Uint8Array): Promise<bigint> {
  const padded = padDg1(dg1)
  const mrz = padded.subarray(5)
  const layout = mrzLayout(padded)
  const country = mrz.subarray(2, 5)
  const fields = concat(
    Buffer.from(country).toString() === "D<<" ? enc("DEU") : country,
    getFullDocumentNumber(padded),
    mrz.subarray(layout.dateOfBirth, layout.dateOfBirth + 6),
    mrz.subarray(layout.expiryDate, layout.expiryDate + 6),
  )
  return poseidon2HashAsync(packBeBytesIntoFields(fields, 31).map((x) => BigInt(x)))
}

export type AttestedSalts = {
  dg1Salt: bigint
  expiryDateSalt: bigint
  dg2HashSalt: bigint
  privateNullifierSalt: bigint
}

/** comm_out of the attested_id circuits, which the disclosure circuits take as comm_in */
export async function calculateAttestedIdCommitment(
  salts: AttestedSalts,
  dg1: Uint8Array,
  portraitHash: Uint8Array,
) {
  const privateNullifier = await calculateTier2PrivateNullifier(dg1)
  const dg2HashNormalized = await normalizeDg2Hash(
    Array.from(calculateAttestedDigest(dg1, portraitHash)),
  )
  const commitment = await hashSaltDg1Dg2HashPrivateNullifier(
    salts,
    Binary.from(padDg1(dg1)),
    String.fromCharCode(...getExpiryDate(dg1)),
    dg2HashNormalized,
    SHA256_IDENTIFIER,
    privateNullifier,
  )
  return { commitment: commitment.toBigInt(), privateNullifier, dg2HashNormalized }
}

export async function calculateAttestationParamCommitment(opts: {
  rootKeyType: number
  rootKey: Uint8Array
  environment: number
  appId: string
  integrityPublicKey?: Uint8Array
  mode: number
}): Promise<bigint> {
  const rootKeyLeaf = await packLeBytesAndHashPoseidon2(
    concat(new Uint8Array([opts.rootKeyType]), opts.rootKey),
  )
  const integrityKeyHash = opts.integrityPublicKey
    ? await packLeBytesAndHashPoseidon2(opts.integrityPublicKey)
    : 0n
  return poseidon2HashAsync([
    PROOF_TYPE_ATTESTED_ID,
    5n,
    rootKeyLeaf,
    BigInt(opts.environment),
    await packLeBytesAndHashPoseidon2(enc(opts.appId)),
    integrityKeyHash,
    BigInt(opts.mode),
  ])
}

export type AttestationOptions = {
  dg1: Uint8Array
  portraitHash: Uint8Array
  salts: AttestedSalts
  appId?: string
  mode?: number
  digest?: Uint8Array
  digestAlgorithmOid?: string
}

function attestedIdBaseInputs(opts: AttestationOptions) {
  const digest = opts.digest ?? calculateAttestedDigest(opts.dg1, opts.portraitHash)
  const clientData = buildClientData({
    mode: opts.mode ?? FACEMATCH_MODE_STRICT,
    digest,
    digestAlgorithmOid: opts.digestAlgorithmOid,
  })
  const s = opts.salts
  return {
    clientData,
    inputs: {
      salted_dg1: {
        value: Array.from(padDg1(opts.dg1)),
        salt: `0x${s.dg1Salt.toString(16)}`,
        hash: "0x0",
      },
      expiry_date_salt: `0x${s.expiryDateSalt.toString(16)}`,
      dg2_hash_salt: `0x${s.dg2HashSalt.toString(16)}`,
      private_nullifier_salt: `0x${s.privateNullifierSalt.toString(16)}`,
      portrait_hash: Array.from(opts.portraitHash),
    },
  }
}

// AAGUID "appattest" + zeros
const AAGUID_PRODUCTION = concat(enc("appattest"), new Uint8Array(7))

export const IOS_APP_ID = "ABCDE12345.app.zkpassport.test"

/** Inputs for attested_id_ios: a synthetic App Attest attestation in the production environment */
export async function buildIosAttestedIdInputs(
  opts: AttestationOptions & { credentialAppId?: string },
) {
  const appId = opts.appId ?? IOS_APP_ID
  const root = Key.p384("ios root")
  const intermediate = Key.p384("ios intermediate")
  const credential = Key.p256("ios credential")
  const { clientData, inputs } = attestedIdBaseInputs(opts)

  const credentialId = sha256(credential.publicKey)
  const coseKey = concat(
    new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    credential.publicKey.subarray(0, 32),
    new Uint8Array([0x22, 0x58, 0x20]),
    credential.publicKey.subarray(32),
  )
  const authData = concat(
    sha256(enc(appId)),
    new Uint8Array([0x40, 0, 0, 0, 0]),
    AAGUID_PRODUCTION,
    new Uint8Array([0x00, credentialId.length]),
    credentialId,
    coseKey,
  )
  const nonce = sha256(concat(authData, await getClientDataHash(clientData)))

  const intermediateTbs = tbsCertificate({
    issuer: "Test App Attestation Root CA",
    subject: "Test App Attestation CA 1",
    signatureOid: OID_ECDSA_SHA384,
    subjectKey: intermediate,
  })
  const credentialTbs = tbsCertificate({
    issuer: "Test App Attestation CA 1",
    subject: Buffer.from(credentialId).toString("hex"),
    signatureOid: OID_ECDSA_SHA256,
    subjectKey: credential,
    extensions: [
      extension(
        OID_APPLE_APP_ID,
        seq(
          tlv([0xbf, 0x89, 0x30], int(1)),
          tlv([0xbf, 0x89, 0x34], octets(enc(opts.credentialAppId ?? appId))),
        ),
      ),
      extension(OID_APPLE_NONCE, seq(tlv(0xa1, octets(nonce)))),
    ],
  })

  return {
    rootKey: root.publicKey,
    appId,
    environment: 1,
    inputs: {
      ...inputs,
      root_key: Array.from(root.publicKey),
      intermediate_key: Array.from(intermediate.publicKey),
      intermediate_tbs: pad(intermediateTbs, 500),
      intermediate_sig: Array.from(root.sign(sha384(intermediateTbs))),
      credential_tbs: pad(credentialTbs, CREDENTIAL_TBS_MAX_LEN),
      credential_sig: Array.from(intermediate.sign(sha256(credentialTbs))),
      auth_data: pad(authData, AUTH_DATA_MAX_LEN),
      client_data: pad(clientData, CLIENT_DATA_MAX_LEN),
      environment: 1,
      app_id: pad(enc(appId), APP_ID_MAX_LEN),
    },
  }
}

export const ANDROID_APP_ID = "app.zkpassport.test"
// base64url('{"alg":"ES256"}')
const JWS_HEADER_BASE64 = "eyJhbGciOiJFUzI1NiJ9"

function androidKeyDescription(appId: string): Uint8Array {
  const attestationApplicationId = seq(
    set(seq(octets(enc(appId)), int(1))),
    set(octets(sha256(enc("signing certificate")))),
  )
  return seq(
    int(200),
    enumerated(1),
    int(200),
    enumerated(1),
    octets(sha256(enc("attestation challenge"))),
    octets(),
    seq(tlv([0xbf, 0x85, 0x45], octets(attestationApplicationId))),
    seq(),
  )
}

/**
 * Inputs for attested_id_android_rk_ecdsa_ik_count_1_ik_ecdsa_p256_sha256: a P-384 root, one P-256
 * intermediate, a key attestation credential certificate and a Play Integrity token that meets
 * every check, so the environment is production.
 */
export async function buildAndroidAttestedIdInputs(
  opts: AttestationOptions & { currentDate: number },
) {
  const appId = opts.appId ?? ANDROID_APP_ID
  const root = Key.p384("android root")
  const intermediate = Key.p256("android intermediate")
  const credential = Key.p256("android credential")
  const playIntegrity = Key.p256("play integrity")
  const { clientData, inputs } = attestedIdBaseInputs(opts)

  const intermediateTbs = tbsCertificate({
    issuer: "Test Key Attestation Root",
    subject: "Test Key Attestation Intermediate",
    signatureOid: OID_ECDSA_SHA384,
    subjectKey: intermediate,
  })
  const credentialTbs = tbsCertificate({
    issuer: "Test Key Attestation Intermediate",
    subject: "Android Keystore Key",
    signatureOid: OID_ECDSA_SHA256,
    subjectKey: credential,
    extensions: [extension(OID_ANDROID_KEY_ATTESTATION, androidKeyDescription(appId))],
  })

  const clientDataHash = await getClientDataHash(clientData)
  const clientDataSig = credential.sign(sha256(clientDataHash))
  const nonce = Buffer.from(sha256(concat(clientDataHash, clientDataSig))).toString("base64url")
  const token = JSON.stringify({
    requestDetails: {
      requestPackageName: appId,
      timestampMillis: `${opts.currentDate * 1000}`,
      nonce: `${nonce}=`,
    },
    appIntegrity: {
      appRecognitionVerdict: "PLAY_RECOGNIZED",
      packageName: appId,
      certificateSha256Digest: ["c2lnbmluZyBjZXJ0aWZpY2F0ZQ"],
      versionCode: "1",
    },
    deviceIntegrity: { deviceRecognitionVerdict: ["MEETS_DEVICE_INTEGRITY"] },
    accountDetails: { appLicensingVerdict: "LICENSED" },
    environmentDetails: { playProtectVerdict: "NO_ISSUES" },
  }).replace("=", "\\u003d")
  const tokenBytes = enc(token)
  const signedPayload = enc(`${JWS_HEADER_BASE64}.${Buffer.from(tokenBytes).toString("base64url")}`)

  return {
    rootKey: root.publicKey,
    appId,
    environment: 1,
    playIntegrityPublicKey: playIntegrity.publicKey,
    inputs: {
      current_date: opts.currentDate,
      ...inputs,
      root_key: Array.from(root.publicKey),
      intermediate_1_key: Array.from(intermediate.publicKey),
      intermediate_1_tbs: pad(intermediateTbs, 700),
      intermediate_1_sig: Array.from(root.sign(sha384(intermediateTbs))),
      credential_key: Array.from(credential.publicKey),
      credential_tbs: pad(credentialTbs, CREDENTIAL_TBS_MAX_LEN),
      credential_sig: Array.from(intermediate.sign(sha256(credentialTbs))),
      client_data: pad(clientData, CLIENT_DATA_MAX_LEN),
      client_data_sig: Array.from(clientDataSig),
      environment: 1,
      app_id: pad(enc(appId), APP_ID_MAX_LEN),
      integrity_token: pad(tokenBytes, INTEGRITY_TOKEN_MAX_LENGTH),
      integrity_token_signature: Array.from(playIntegrity.sign(sha256(signedPayload))),
      play_integrity_public_key: Array.from(playIntegrity.publicKey),
    },
  }
}

export { ATTESTATION_KEY_TYPE_APPLE, ATTESTATION_KEY_TYPE_GOOGLE }
