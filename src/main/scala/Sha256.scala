package hashing

object Sha256 {
  /*
  Symbols and Operations
      The following symbols are used in the secure hash algorithm specifications; each operates on w-bit words:

      ∧ Bitwise AND operation.
      ∨ Bitwise OR (“inclusive-OR”) operation.
      ⊕ Bitwise XOR (“exclusive-OR”) operation.
      ¬ Bitwise complement operation.
      + Addition modulo 2w.
      << Left-shift operation, where x << n is obtained by discarding the left-most n bits of the word x
          and then padding the result with n zeroes on the right.
      >> Right-shift operation, where x >> n is obtained by discarding the rightmost n bits of the word x
          and then padding the result with n zeroes on the left.
  */


  val BLOCK_SIZE = 64
  val DIGEST_SIZE = 32
  val BITS_IN_WORD = 32  // w - Number of bits in a word.

  // SHA-224 and SHA-256 use the same sequence of sixty-four constant 32-bit words.These words represent
  // the first thirty-two bits of the fractional parts of the cube roots of the first sixty-four prime numbers.
  val SEQ = Seq(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  )

  /*
    Before hash computation begins for each of the secure hash algorithms, the initial hash value,
    H(0), must be set. The size and number of words in H(0) depends on the message digest size.
    For SHA-256, the initial hash value, H(0), shall consist of the following eight 32-bit words, in hex:
  */

  val DIGEST: Seq[Int] = Seq(
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
  )

  val empty_block: Seq[Int] = (0 until BLOCK_SIZE).map(i => 0)

  case class ShaInfo(
                      var digest:Seq[Int]=DIGEST,
                      var count_lo:Int=0,
                      var count_hi:Int=0,
                      var data:Seq[Int]=empty_block)

  // The right shift operation SHR n(x), where x is a w-bit word and n is an integer with 0 ≤ n < w, is defined by SHR n (x)=x >> n.
  def shiftRight(x: Int, n: Int): Int = (x & 0xffffffff) >> n

  //The rotate right (circular right shift) operation, where x is a w-bit word
  //  and n is an integer with 0 ≤ n < w, is defined by ROTR n (x) =(x >> n) ∨ (x << w - n).
  def rotateRight(x: Int, y: Int): Int = (((x & 0xffffffff) >> (y & 31)) | (x << (BITS_IN_WORD - (y & 31)))) & 0xffffffff

  /*
    SHA256 uses six logical functions, where each function operates on 64-bit words,
    which are represented as x, y, and z. The result of each function is a new 64-bit word.
  */


  // The x input chooses if the output is from y or z: Ch(x,y,z)=(x∧y)⊕(¬x∧z)
  def choose(x: Int, y: Int, z: Int): Int = z ^ (x & (y ^ z))

  /*The result is set according to the majority of the 3 inputs.

    Maj(x, y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ ( y ∧ z)

    The functions are defined for bit vectors (of 32 bits in case fo SHA-256)
   */
  def majority(x: Int, y: Int, z: Int): Int = ((x | y) & z) | (x & y)

  // ROTR 2(x) ⊕ ROTR 13(x) ⊕ ROTR 22(x)
  def sigma0(x: Int): Int = rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22)


  // ROTR 6(x) ⊕ ROTR 11(x) ⊕ ROTR 25(x)
  def sigma1(x: Int): Int = rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25)

  // ROTR 7(x) ⊕ ROTR 18(x) ⊕ SHR 3(x)
  def gamma0(x: Int): Int = rotateRight(x, 7) ^ rotateRight(x, 18) ^ shiftRight(x, 3)

  // ROTR 17(x) ⊕ ROTR 19(x) ⊕ SHR 10(x)
  def gamma1(x: Int): Int = rotateRight(x, 17) ^ rotateRight(x, 19) ^ shiftRight(x, 10)

  def mutate(sha: ShaInfo): Seq[Int] = {
    var W: Seq[Int] = (0 until 16).map {
      i: Int => Seq(
        sha.data(4 * i + 0) << 24,
        sha.data(4 * i + 1) << 16,
        sha.data(4 * i + 2) << 8,
        sha.data(4 * i + 3) << 0
      ).sum
    }

    (16 until 64).foreach {i =>
      val sum = gamma1(W(i - 2)) + W(i - 7) + gamma0(W(i - 15)) + W(i - 16)
      W = W :+ (sum & 0xffffffff)
    }

    var digest = Seq[Int](sha.digest:_*)

    (0 until -64 by -1).foreach{ idx: Int =>
      val i: Int = Math.abs(idx % 8)
      // Initialize the eight working variables, a, b, c, d, e, f, g, and h  with the (i-1)st hash value.
      // W is the prepared message schedule.

      val positions = (0 until 8).map { x => (i + x) % 8 }
      val Seq(a, b, c, d, e, f, g, h) = positions.map(digest)
      val List(t0_idx, t1_idx) = List(3, 7).map{ z => (i + z) % 8 }
      val t0: Int = h + sigma1(e) + choose(e, f, g) + SEQ(Math.abs(idx)) + W(Math.abs(idx))
      val t1: Int = sigma0(a) + majority(a, b, c)
      digest = digest.updated(t0_idx, (d + t0) & 0xffffffff)
      digest = digest.updated(t1_idx, (t0 + t1) & 0xffffffff)
    }
    sha.digest.zipWithIndex.map{ case (x, idx) => (x + digest(idx)) & 0xffffffff }
  }

  def shaUpdate(buff: String): ShaInfo = {
    val sha = ShaInfo()
    var count = buff.length
    val count_lo = (sha.count_lo + (count << 3)) & 0xffffffff
    if (count_lo < sha.count_lo) {
      sha.count_hi += 1
    }
    sha.count_lo = count_lo
    sha.count_hi += (count >> 29)

    var buffIndex = 0
    while (count >= BLOCK_SIZE) {
      sha.data = buff.slice(buffIndex, buffIndex + BLOCK_SIZE).map(_.toInt)
      count -= BLOCK_SIZE
      buffIndex += BLOCK_SIZE
      sha.digest = mutate(sha)
    }

    buff.slice(buffIndex, buffIndex + count).zipWithIndex.foreach{
      case (c:Char, idx:Int) => sha.data = sha.data.updated(idx, c.toInt)
    }

    sha
  }

  def sha256HexDigest(string: String): String = {
    val sha = shaUpdate(string)
    var count = (sha.count_lo >> 3) & 0x3f
    sha.data = sha.data.updated(count, 0x80)

    count += 1
    if (count > BLOCK_SIZE - 8) {
      // fill with zero bytes after the count
      sha.data = sha.data.take(count) ++ (0 until BLOCK_SIZE - count).map{_=>0}
      sha.digest = mutate(sha)
      sha.data = (0 until BLOCK_SIZE).map{_=>0}
    } else {
      sha.data = sha.data.take(count) ++ (0 until BLOCK_SIZE - count).map{_=>0}
    }

    (56 until 64).zip((0 until 2).flatMap{_=>24 until -1 by -8}).foreach{
      case (idx: Int, shift: Int) =>
        sha.data = sha.data.updated(idx, (if (idx < 60) sha.count_hi else sha.count_lo >> shift) & 0xff)
    }

    val digest = mutate(sha).flatMap{ i => (24 until -1 by -8).map{ shift => (i >> shift) & 0xff } }
    digest.take(DIGEST_SIZE).map(i => f"$i%02x").mkString("")
  }

  def main(args: Array[String]): Unit = {
    val string = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
    val expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    println(sha256HexDigest(string))
  }

}
