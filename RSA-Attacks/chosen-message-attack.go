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
func txtBookRSA(bitSize int) (*big.Int, *big.Int, *big.Int) {

	e := big.NewInt(65537)

	// Generate p, q
	p := genPrime(bitSize / 2)
	q := genPrime(bitSize / 2)

	// Calculate N = p*q
	N := new(big.Int).Mul(p, q)

	// Calculate phi = (p-1)*(q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1)) // (p-1)
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1)) // (q-1)
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	// Calculate d the modular inverse of e mod phi
	d := new(big.Int).ModInverse(e, phi)

	return e, d, N // (e, N) public parameters - Private parameters (d, p, q)

}

// Function that signs a message m -> sig = m^(d) mod N
func SignatureGeneration(m, d, N *big.Int) *big.Int {
	//m := new(big.Int).SetBytes(message)
	//m := big.NewInt(int64(message))
	sig := new(big.Int).Exp(m, d, N) // sig = m^d mod N
	return sig
}

// Function that verifies a signature
func SignaturVerification(m, sig, e, N *big.Int) bool {
	mP := new(big.Int).Exp(sig, e, N) // m = sig^e mod N

	// Comparing big.Ints
	//if mP.Cmp(m) != 0 {
	//return false
	//}
	//return true
	return mP.Cmp(m) == 0
}

// Function to forge signatures
func ForgeSingature(m, d, N *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {

	// Generate a random r
	rand.Seed(time.Now().UnixNano())

	// Choose random r s.t gcd(r, N) = 1
	var r *big.Int
	for {
		var err error
		r, err = crand.Int(crand.Reader, N)
		if err != nil {
			panic(err)
		}

		if new(big.Int).GCD(nil, nil, r, N).Cmp(big.NewInt(1)) == 0 {
			break
		}
	}

	// Calculate r^(-1) mod N
	rInv := new(big.Int).ModInverse(r, N)

	// set m1 = r; m2 = m * r^(-1) mod N
	m1 := r
	m2 := new(big.Int).Mul(m, rInv)
	m2.Mod(m2, N)

	// Send m1 and m2 to the signing oracle
	sig1 := SignatureGeneration(m1, d, N)
	sig2 := SignatureGeneration(m2, d, N)

	// Calculate sigM = sig1 * sig2
	sigM := new(big.Int).Mul(sig1, sig2)
	// SigM mod N
	sigM.Mod(sigM, N)

	return sigM, m1, sig1, m2
}

func main() {

	// Generate RSA parameters
	e, d, N := txtBookRSA(2048)
	fmt.Println()

	fmt.Println("Signatures with textbook RSA.\n")
	// Message we want to forge (refernece: https://www.youtube.com/watch?v=crdRO72vWyA&t=3s)
	m := "Yes, I'm schh-eduled to meet Count Dracula."
	fmt.Printf("Message we want to forge a signature for M = '%s'\n", m)
	// Convert string to bytes
	mBytes := []byte(m)

	// Convert to big.Int
	mInt := new(big.Int).SetBytes(mBytes)
	fmt.Println("Message M converted to integer:", mInt.String()[:5]) // mInt is a big integer, so we print out the first 5 digits
	fmt.Println()
	sigM, m1, _, m2 := ForgeSingature(mInt, d, N)
	fmt.Println("M1 = r => ", m1.String()[:5])
	fmt.Println("M2 = M * r ^(-1) mod N => ", m2.String()[:5])
	fmt.Println()
	// Signing oracle
	sig2 := SignatureGeneration(m2, d, N)
	sig1 := SignatureGeneration(m1, d, N)

	fmt.Println("Generating signatures for M1 and M2:")
	fmt.Println("< M1:", m1.String()[:5], ", sig1:", sig1.String()[:5], ">")
	fmt.Println("< M2:", m2.String()[:5], ", sig2:", sig2.String()[:5], ">")

	fmt.Println()

	fmt.Printf("Verifying <M1, sig1>: %t\n", SignaturVerification(m1, sig1, e, N)) // Calling function within the print statement
	fmt.Printf("Verifying <M2, sig2>: %t\n", SignaturVerification(m2, sig2, e, N))

	fmt.Println()

	fmt.Println("Compute sigM = sig1 * sig2 => ", sigM.String()[:5])
	fmt.Println("Send <M, sigM> to the verifying algorithm: ", SignaturVerification(mInt, sigM, e, N))

}
