package Sha256TestSpec

import org.scalatest.{FlatSpec, Matchers}

class Sha256TestSpec extends FlatSpec with Matchers {

  val auctionID = "1"

  "Sha256" should "hash" in {
    val string = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
    val expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    val hashed = hashing.Sha256.sha256HexDigest(string)
    hashed should be (expected)
  }
}