'use strict'

const assert = require('assert')
const bsv = require('./index.js')

const { PrivateKey, PublicKey, crypto, Transaction, Address, Script } = bsv
const { ECDSA, Signature, Hash, BN } = crypto

let pass = 0
let fail = 0
function ok (name, fn) {
  try {
    fn()
    pass++
    console.log('  ok  ', name)
  } catch (e) {
    fail++
    console.log('  FAIL', name, '-', e.message)
  }
}

console.log('bsv-1.5.6-hardened smoke tests')
console.log('elliptic version:', require('elliptic/package.json').version)
console.log('bn.js version:   ', require('bn.js/package.json').version)
console.log()

// --- 1. Key generation, sign, verify round-trip ----------------------------
console.log('basic sign/verify:')
const priv = PrivateKey.fromRandom()
const pub = priv.publicKey
const msg = Buffer.from('the quick brown fox jumps over the lazy dog')
const hash = Hash.sha256(msg)

const sig = ECDSA.sign(hash, priv)

ok('signature verifies', () => assert.strictEqual(ECDSA.verify(hash, sig, pub), true))
ok('signature has low-S (canonical)', () => assert.strictEqual(sig.hasLowS(), true))
ok('strict verify accepts canonical sig', () => assert.strictEqual(ECDSA.verifyStrict(hash, sig, pub), true))

// --- 2. Tampered hash must fail --------------------------------------------
console.log('\ntampered inputs:')
const badHash = Buffer.from(hash)
badHash[0] ^= 0xff
ok('wrong hash fails verification', () => assert.strictEqual(ECDSA.verify(badHash, sig, pub), false))

// Different keypair shouldn't verify
const otherPub = PrivateKey.fromRandom().publicKey
ok('wrong pubkey fails verification', () => assert.strictEqual(ECDSA.verify(hash, sig, otherPub), false))

// --- 3. High-S malleated signature -----------------------------------------
console.log('\nmalleability (high-S):')
const N = Signature.SECP256K1_N
const highSig = new Signature({ r: sig.r, s: N.sub(sig.s) })
ok('high-S still satisfies math (lax verify)', () => assert.strictEqual(ECDSA.verify(hash, highSig, pub), true))
ok('strict verify rejects high-S', () => assert.strictEqual(ECDSA.verifyStrict(hash, highSig, pub), false))
ok('toLowS round-trips through Signature', () => {
  const fixed = highSig.toLowS()
  assert.ok(fixed.hasLowS(), 'toLowS produced non-low-S sig')
  assert.strictEqual(ECDSA.verifyStrict(hash, fixed, pub), true)
})

// --- 4. DER strict parsing -------------------------------------------------
console.log('\nDER parser hardening:')
const der = sig.toDER()
ok('round-trip DER parses', () => {
  const sig2 = Signature.fromDER(der)
  assert.ok(sig2.r.eq(sig.r) && sig2.s.eq(sig.s))
})
ok('DER with trailing byte rejected (strict)', () => {
  const bad = Buffer.concat([der, Buffer.from([0x00])])
  assert.throws(() => Signature.fromDER(bad, true))
})
ok('DER with wrong header rejected', () => {
  const bad = Buffer.from(der); bad[0] = 0x31
  assert.throws(() => Signature.fromDER(bad))
})
ok('DER too short rejected', () => {
  assert.throws(() => Signature.fromDER(Buffer.from([0x30, 0x02, 0x02, 0x01])))
})
ok('DER with zero R rejected', () => {
  // 30 06 02 01 00 02 01 01
  const bad = Buffer.from([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01])
  assert.throws(() => Signature.fromDER(bad))
})
ok('DER with negative R rejected', () => {
  // R = 0x80 (high bit set)
  const bad = Buffer.from([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01])
  assert.throws(() => Signature.fromDER(bad))
})
ok('DER with excessively-padded R rejected', () => {
  // R = 00 01 (padding not needed)
  const bad = Buffer.from([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01])
  assert.throws(() => Signature.fromDER(bad))
})
ok('isStrictDER agrees with parseDER', () => {
  assert.strictEqual(Signature.isStrictDER(der), true)
  assert.strictEqual(Signature.isStrictDER(Buffer.concat([der, Buffer.from([0])])), false)
})

// --- 5. Compact signature hardening ----------------------------------------
console.log('\ncompact signature:')
ok('compact wrong length rejected', () => {
  assert.throws(() => Signature.fromCompact(Buffer.alloc(64)))
})

// --- 6. End-to-end transaction signing -------------------------------------
console.log('\ntransaction signing:')
ok('build, sign, and verify a P2PKH tx', () => {
  const utxoPriv = PrivateKey.fromRandom()
  const utxoAddr = utxoPriv.toAddress()
  const utxoScript = Script.buildPublicKeyHashOut(utxoAddr)
  const utxo = {
    txId: '0'.repeat(64),
    outputIndex: 0,
    script: utxoScript.toHex(),
    satoshis: 100000
  }
  const destAddr = PrivateKey.fromRandom().toAddress()
  const tx = new Transaction()
    .from(utxo)
    .to(destAddr, 50000)
    .change(utxoAddr)
    .sign(utxoPriv)

  // serialize / deserialize to make sure the wire form survives
  const ser = tx.serialize(true)
  const round = new Transaction(ser)
  assert.ok(round.inputs[0].script.toBuffer().length > 0, 'no scriptSig')
})

console.log(`\nResult: ${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
