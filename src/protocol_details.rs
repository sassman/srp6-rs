/*!
A very brief summary of the papers and RFCs of SRP6 and SRP6a

## SRP Vocabulary

```plain
N    A large safe prime                     (N = 2q+1, where q is prime)
     All arithmetic is done modulo N.
g    A generator modulo N
k    Multiplier parameter                   (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
s    User's salt
I    Username                               (the rfc calls it U)
p    Cleartext Password
H()  One-way hash function
^    (Modular) Exponentiation
u    Random scrambling parameter
a,b  Secret ephemeral values
A,B  Public ephemeral values
x    Private key                            (derived from p and s)
v    Password verifier
S    Session key
K    Strong session key                     (SHA1 interleaved)
M    Proof (calculated by the server)
M1   Proof provided by the client
```

## SRP Formulas

Calculations by the client:
```plain
I, p = <read from user>
N, g, s, B = <read from server>
a = random()
A = g^a % N
u = SHA1(PAD(A) | PAD(B))
k = SHA1(N | PAD(g))                        (k = 3 for legacy SRP-6)
x = SHA1(s | SHA1(I | ":" | p))
S = (B - (k * g^x)) ^ (a + (u * x)) % N
K = SHA_Interleave(S)
M = H(H(N) XOR H(g) | H(U) | s | A | B | K)
```

Calculations by the server:
```plain
N, g, s, v = <read from password file>
v = g^x % N
b = random()
k = SHA1(N | PAD(g))
B = k*v + g^b % N
A = <read from client>
u = SHA1(PAD(A) | PAD(B))
S = (A * v^u) ^ b % N
K = SHA_Interleave(S)

H(A | M | K)
```

## Safeguards
1. The user will abort if he receives one of
    - `B mod N == 0`
    - `u == 0`
2. The host will abort if it detects that `A mod N == 0`.
3. The user must show his proof of `K` first. If the server detects that the user's proof is incorrect, it must abort without showing its own proof of `K`.

## References
- [EKE](https://en.wikipedia.org/wiki/Encrypted_key_exchange)
- [papers](http://srp.stanford.edu/doc.html#papers)
- [design](http://srp.stanford.edu/design.html)
- [rfc](https://datatracker.ietf.org/doc/html/rfc2945)
- [vetted N](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A)
*/
