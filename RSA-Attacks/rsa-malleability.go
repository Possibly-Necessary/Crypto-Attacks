package main

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

var smallPrimes = []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
	31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
	73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
	127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
	179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
}

// randBigIntRange generates a random big.Int in the range [min, max].
func randBigIntRange(min, max *big.Int) *big.Int {
	// Calculate the range delta = max - min + 1
	delta := new(big.Int).Sub(max, min)
	delta = delta.Add(delta, big.NewInt(1))

	// Generate a random number in [0, delta)
	randNum, err := crand.Int(crand.Reader, delta)
	if err != nil {
		panic(err)
	}

	// Shift the random number into the range [min, max]
	randNum = randNum.Add(randNum, min)
	return randNum
}

// Rabin-Miller primality test
func RabinMiller(n *big.Int, k int) bool {

	if n.Cmp(big.NewInt(2)) == 0 { // Check if n == 2
		return true
	}

	if new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return false
	}

	// Decompose n-1 into 2^(r*s) - r and s will represent the decomposition of n-1 into 2^(r*s)
	s := new(big.Int).Sub(n, big.NewInt(1)) // Subtract 1 from n and storing it in s
	r := 0
	if new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		s.Rsh(s, 1) // s = s/2
		r++
	}
	// Seed the rng
	rand.Seed(time.Now().UnixNano())

	// Run the Rabin-Miller
	for i := 0; i < k; i++ { // Generate random big.Int a in the range [2, n-2]
		a := randBigIntRange(big.NewInt(2), new(big.Int).Sub(n, big.NewInt(2)))
		x := new(big.Int).Exp(a, s, n) // Compute x = a^s mod n using big.Int's Exp method

		if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
			continue
		}

		xIsMinusOne := false
		for j := 0; j < r-1; j++ {
			x.Exp(x, big.NewInt(2), n)
			if x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
				xIsMinusOne = true
				break
			}
		}

		if !xIsMinusOne {
			return false
		}
	}
	return true
}

func genPrime(n int) *big.Int {
	rand.Seed(time.Now().UnixNano())

	// 1<<uint(n-1) Create a big.Int representing 2^(n-1)
	min := new(big.Int).Lsh(big.NewInt(1), uint(n-1))
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(n)), big.NewInt(1))

	for {
		p := randBigIntRange(min, max) // Generate a random odd number of bits
		p.Or(p, big.NewInt(1))

		// Check divisibility by small primes
		div := false
		for _, smallPrime := range smallPrimes {
			if new(big.Int).Mod(p, big.NewInt(smallPrime)).Cmp(big.NewInt(0)) == 0 {
				div = true
				break
			}
		}
		if div {
			continue
		}
		if RabinMiller(p, 40) {
			return p
		}
	}
}

// A function that implements (textbook) RSA to generate RSA parameters
func txtBookRSA(bitSize int) (*big.Int, *big.Int, *big.Int) { // Returns e, d, N of type big.Int

	e := big.NewInt(65537) // Common choice for e

	// Generate p, q
	p := genPrime(bitSize / 2)
	q := genPrime(bitSize / 2)

	// Calculate N = p*q
	N := new(big.Int).Mul(p, q)

	// Calculate phi = (p-1)*(q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1)) // (p-1)
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1)) // (q-1)
	phi := new(big.Int).Mul(pMinus1, qMinus1) // (p-1)*(q-1)

	// Calculate d the modular inverse of e mod phi
	d := new(big.Int).ModInverse(e, phi)

	return e, d, N // (e, N) public parameters

}

// Encryption/Decryption using the textbook RSA we defined earlier
// Function that encryptes messages using the public key (e, N)
func Encrypt(m, e, N *big.Int) *big.Int { // Will change from accepting messages as []bytes to int
	//m := new(big.Int).SetBytes(message)
	//m := big.NewInt(int64(message))
	c := new(big.Int).Exp(m, e, N) // c = m^e mod N
	return c
}

// Function that decrypts messages using the private key 
func Decrypt(c, d, N *big.Int) int {
	m := new(big.Int).Exp(c, d, N) // m = c^d mod N

	// Convert the decrypted message from bytes to string
	//return string(m.Bytes())
	return int(m.Int64())
}

// Function that will demonstrate RSA's malleability
func Malleable(c, r *big.Int) *big.Int {

	// r * c --> (r^e mod N) * (c^e mod N)
	rc := new(big.Int).Mul(c, r)

	return rc
}

func main() {

	// Generate RSA parameters
	e, d, N := txtBookRSA(2048)
	fmt.Println()

	// Encrypting 100
	fmt.Println("Encrypting m = 100 using textbook RSA.\n")
	m := big.NewInt(100) // convert to big.Int

	c := Encrypt(m, e, N) // Encrypt using public key (e, N)

	fmt.Println("Multiply cipher text c by r = 2^e (mod N) to produce c'.\n")

	r := big.NewInt(2)
	re := new(big.Int).Exp(r, e, N) // r^e (mod N)
	rc := Malleable(c, re)

	// Decrypt using the  private key
	rm := Decrypt(rc, d, N)
	fmt.Println("Decrypting the modified cipher text c' => ", rm)

}
