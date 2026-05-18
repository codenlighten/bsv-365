'use strict'

var BN = require('./bn')
var _ = require('../util/_')
var $ = require('../util/preconditions')
var JSUtil = require('../util/js')

var Signature = function Signature (r, s) {
  if (!(this instanceof Signature)) {
    return new Signature(r, s)
  }
  if (r instanceof BN) {
    this.set({
      r: r,
      s: s
    })
  } else if (r) {
    var obj = r
    this.set(obj)
  }
}

Signature.prototype.set = function (obj) {
  this.r = obj.r || this.r || undefined
  this.s = obj.s || this.s || undefined

  this.i = typeof obj.i !== 'undefined' ? obj.i : this.i // public key recovery parameter in range [0, 3]
  this.compressed = typeof obj.compressed !== 'undefined'
    ? obj.compressed : this.compressed // whether the recovered pubkey is compressed
  this.nhashtype = obj.nhashtype || this.nhashtype || undefined
  return this
}

Signature.fromCompact = function (buf) {
  $.checkArgument(Buffer.isBuffer(buf), 'Argument is expected to be a Buffer')
  $.checkArgument(buf.length === 65, new Error('Compact signature must be 65 bytes'))

  var sig = new Signature()

  var compressed = true
  var i = buf.slice(0, 1)[0] - 27 - 4
  if (i < 0) {
    compressed = false
    i = i + 4
  }

  var b2 = buf.slice(1, 33)
  var b3 = buf.slice(33, 65)

  $.checkArgument(i === 0 || i === 1 || i === 2 || i === 3, new Error('i must be 0, 1, 2, or 3'))
  $.checkArgument(b2.length === 32, new Error('r must be 32 bytes'))
  $.checkArgument(b3.length === 32, new Error('s must be 32 bytes'))

  sig.compressed = compressed
  sig.i = i
  sig.r = BN.fromBuffer(b2)
  sig.s = BN.fromBuffer(b3)

  $.checkArgument(!sig.r.isZero(), new Error('Compact signature r must be non-zero'))
  $.checkArgument(!sig.s.isZero(), new Error('Compact signature s must be non-zero'))

  return sig
}

Signature.fromDER = Signature.fromBuffer = function (buf, strict) {
  var obj = Signature.parseDER(buf, strict)
  var sig = new Signature()

  sig.r = obj.r
  sig.s = obj.s

  return sig
}

// The format used in a tx
Signature.fromTxFormat = function (buf) {
  var nhashtype = buf.readUInt8(buf.length - 1)
  var derbuf = buf.slice(0, buf.length - 1)
  var sig = Signature.fromDER(derbuf, false)
  sig.nhashtype = nhashtype
  return sig
}

Signature.fromString = function (str) {
  var buf = Buffer.from(str, 'hex')
  return Signature.fromDER(buf)
}

/**
 * In order to mimic the non-strict DER encoding of OpenSSL, set strict = false.
 *
 * Hardened: this parser is bounds-checked end-to-end and rejects negative,
 * zero, and excessively-padded R/S even in non-strict mode. In strict mode
 * it additionally enforces full BIP66 (no trailing bytes, exact length byte,
 * minimal integer encoding).
 */
Signature.parseDER = function (buf, strict) {
  $.checkArgument(Buffer.isBuffer(buf), new Error('DER formatted signature should be a buffer'))
  if (_.isUndefined(strict)) {
    strict = true
  }

  // Minimum DER ECDSA signature: 30 06 02 01 R 02 01 S = 8 bytes.
  // Maximum (with 33-byte R and S incl. leading 0x00 pad): 0x46 = 70 bytes body + 2 hdr = 72.
  $.checkArgument(buf.length >= 8, new Error('DER signature too short'))
  $.checkArgument(buf.length <= 72, new Error('DER signature too long'))

  var header = buf[0]
  $.checkArgument(header === 0x30, new Error('Header byte should be 0x30'))

  var length = buf[1]
  var buflength = buf.length - 2
  $.checkArgument(!strict || length === buflength, new Error('Length byte should match length of what follows'))
  $.checkArgument(length <= buflength, new Error('Length byte longer than buffer'))
  length = length < buflength ? length : buflength

  // R integer header
  $.checkArgument(buf.length > 3, new Error('DER signature truncated before R'))
  var rheader = buf[2]
  $.checkArgument(rheader === 0x02, new Error('Integer byte for r should be 0x02'))

  var rlength = buf[3]
  $.checkArgument(rlength > 0, new Error('Length of r is zero'))
  $.checkArgument(4 + rlength <= buf.length, new Error('Length of r past end of buffer'))
  // Need at least 2 bytes after R for the S header+length, plus 1 byte of S.
  $.checkArgument(4 + rlength + 3 <= buf.length, new Error('Buffer too short for S header'))
  var rbuf = buf.slice(4, 4 + rlength)
  $.checkArgument(rlength === rbuf.length, new Error('Length of r incorrect'))
  $.checkArgument(!(rbuf[0] & 0x80), new Error('R value is negative'))
  if (rlength > 1) {
    $.checkArgument(!(rbuf[0] === 0x00 && !(rbuf[1] & 0x80)), new Error('R value excessively padded'))
  }
  var r = BN.fromBuffer(rbuf)
  $.checkArgument(!r.isZero(), new Error('R value is zero'))
  var rneg = false // enforced above

  // S integer header
  var sheaderIdx = 4 + rlength
  var sheader = buf[sheaderIdx]
  $.checkArgument(sheader === 0x02, new Error('Integer byte for s should be 0x02'))

  var slength = buf[sheaderIdx + 1]
  $.checkArgument(slength > 0, new Error('Length of s is zero'))
  var sStart = sheaderIdx + 2
  $.checkArgument(sStart + slength <= buf.length, new Error('Length of s past end of buffer'))
  var sbuf = buf.slice(sStart, sStart + slength)
  $.checkArgument(slength === sbuf.length, new Error('Length of s incorrect'))
  $.checkArgument(!(sbuf[0] & 0x80), new Error('S value is negative'))
  if (slength > 1) {
    $.checkArgument(!(sbuf[0] === 0x00 && !(sbuf[1] & 0x80)), new Error('S value excessively padded'))
  }
  var s = BN.fromBuffer(sbuf)
  $.checkArgument(!s.isZero(), new Error('S value is zero'))
  var sneg = false

  var sumlength = 2 + 2 + rlength + 2 + slength
  $.checkArgument(length === sumlength - 2, new Error('Length of signature incorrect'))
  // In strict mode, no trailing bytes are permitted.
  $.checkArgument(!strict || buf.length === sumlength, new Error('Trailing bytes after DER signature'))

  var obj = {
    header: header,
    length: length,
    rheader: rheader,
    rlength: rlength,
    rneg: rneg,
    rbuf: rbuf,
    r: r,
    sheader: sheader,
    slength: slength,
    sneg: sneg,
    sbuf: sbuf,
    s: s
  }

  return obj
}

/**
 * Strict BIP66 DER check on a raw signature buffer (without nhashtype).
 * Mirrors Signature.isTxDER but for non-tx DER, where buf.length === buf[1] + 2.
 */
Signature.isStrictDER = function (buf) {
  if (!Buffer.isBuffer(buf)) return false
  try {
    Signature.parseDER(buf, true)
    return true
  } catch (e) {
    return false
  }
}

Signature.prototype.toCompact = function (i, compressed) {
  i = typeof i === 'number' ? i : this.i
  compressed = typeof compressed === 'boolean' ? compressed : this.compressed

  if (!(i === 0 || i === 1 || i === 2 || i === 3)) {
    throw new Error('i must be equal to 0, 1, 2, or 3')
  }

  var val = i + 27 + 4
  if (compressed === false) {
    val = val - 4
  }
  var b1 = Buffer.from([val])
  var b2 = this.r.toBuffer({
    size: 32
  })
  var b3 = this.s.toBuffer({
    size: 32
  })
  return Buffer.concat([b1, b2, b3])
}

Signature.prototype.toBuffer = Signature.prototype.toDER = function () {
  var rnbuf = this.r.toBuffer()
  var snbuf = this.s.toBuffer()

  var rneg = !!(rnbuf[0] & 0x80)
  var sneg = !!(snbuf[0] & 0x80)

  var rbuf = rneg ? Buffer.concat([Buffer.from([0x00]), rnbuf]) : rnbuf
  var sbuf = sneg ? Buffer.concat([Buffer.from([0x00]), snbuf]) : snbuf

  var rlength = rbuf.length
  var slength = sbuf.length
  var length = 2 + rlength + 2 + slength
  var rheader = 0x02
  var sheader = 0x02
  var header = 0x30

  var der = Buffer.concat([Buffer.from([header, length, rheader, rlength]), rbuf, Buffer.from([sheader, slength]), sbuf])
  return der
}

Signature.prototype.toString = function () {
  var buf = this.toDER()
  return buf.toString('hex')
}

/**
 * This function is translated from bitcoind's IsDERSignature and is used in
 * the script interpreter.  This "DER" format actually includes an extra byte,
 * the nhashtype, at the end. It is really the tx format, not DER format.
 *
 * A canonical signature exists of: [30] [total len] [02] [len R] [R] [02] [len S] [S] [hashtype]
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 */
Signature.isTxDER = function (buf) {
  if (buf.length < 9) {
    //  Non-canonical signature: too short
    return false
  }
  if (buf.length > 73) {
    // Non-canonical signature: too long
    return false
  }
  if (buf[0] !== 0x30) {
    //  Non-canonical signature: wrong type
    return false
  }
  if (buf[1] !== buf.length - 3) {
    //  Non-canonical signature: wrong length marker
    return false
  }
  var nLenR = buf[3]
  if (5 + nLenR >= buf.length) {
    //  Non-canonical signature: S length misplaced
    return false
  }
  var nLenS = buf[5 + nLenR]
  if ((nLenR + nLenS + 7) !== buf.length) {
    //  Non-canonical signature: R+S length mismatch
    return false
  }

  var R = buf.slice(4)
  if (buf[4 - 2] !== 0x02) {
    //  Non-canonical signature: R value type mismatch
    return false
  }
  if (nLenR === 0) {
    //  Non-canonical signature: R length is zero
    return false
  }
  if (R[0] & 0x80) {
    //  Non-canonical signature: R value negative
    return false
  }
  if (nLenR > 1 && (R[0] === 0x00) && !(R[1] & 0x80)) {
    //  Non-canonical signature: R value excessively padded
    return false
  }

  var S = buf.slice(6 + nLenR)
  if (buf[6 + nLenR - 2] !== 0x02) {
    //  Non-canonical signature: S value type mismatch
    return false
  }
  if (nLenS === 0) {
    //  Non-canonical signature: S length is zero
    return false
  }
  if (S[0] & 0x80) {
    //  Non-canonical signature: S value negative
    return false
  }
  if (nLenS > 1 && (S[0] === 0x00) && !(S[1] & 0x80)) {
    //  Non-canonical signature: S value excessively padded
    return false
  }
  return true
}

/**
 * Compares to bitcoind's IsLowDERSignature
 * See also ECDSA signature algorithm which enforces this.
 * See also BIP 62, "low S values in signatures"
 */
Signature.prototype.hasLowS = function () {
  if (this.s.lt(new BN(1)) ||
    this.s.gt(new BN('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', 'hex'))) {
    return false
  }
  return true
}

// secp256k1 curve order n.
Signature.SECP256K1_N = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex')

/**
 * Return a Signature equivalent to this one but with low-S enforced (s replaced
 * by n - s if it was high). Idempotent. Defeats ECDSA signature malleability
 * by canonicalizing the form before serialization or verification.
 */
Signature.prototype.toLowS = function () {
  if (this.hasLowS()) {
    return new Signature({
      r: this.r,
      s: this.s,
      i: this.i,
      compressed: this.compressed,
      nhashtype: this.nhashtype
    })
  }
  return new Signature({
    r: this.r,
    s: Signature.SECP256K1_N.sub(this.s),
    i: typeof this.i === 'number' ? this.i ^ 1 : this.i,
    compressed: this.compressed,
    nhashtype: this.nhashtype
  })
}

/**
 * @returns true if the nhashtype is exactly equal to one of the standard options or combinations thereof.
 * Translated from bitcoind's IsDefinedHashtypeSignature
 */
Signature.prototype.hasDefinedHashtype = function () {
  if (!JSUtil.isNaturalNumber(this.nhashtype)) {
    return false
  }
  // accept with or without Signature.SIGHASH_ANYONECANPAY by ignoring the bit
  var temp = this.nhashtype & 0x1F
  if (temp < Signature.SIGHASH_ALL || temp > Signature.SIGHASH_SINGLE) {
    return false
  }
  return true
}

Signature.prototype.toTxFormat = function () {
  var derbuf = this.toDER()
  var buf = Buffer.alloc(1)
  buf.writeUInt8(this.nhashtype, 0)
  return Buffer.concat([derbuf, buf])
}

Signature.SIGHASH_ALL = 0x01
Signature.SIGHASH_NONE = 0x02
Signature.SIGHASH_SINGLE = 0x03
Signature.SIGHASH_FORKID = 0x40
Signature.SIGHASH_ANYONECANPAY = 0x80

module.exports = Signature
