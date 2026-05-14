Modulet dhe Funksionalitetet
1. RSA Factorization Attack (Opsioni 1)
Faktorizon modulin n të një RSA-1024 duke përdorur tre strategji të kombinuara: Fermat's Factorization (për prime të afërta me √n), trial division dhe Pollard's Rho si fallback probabilistik. Kjo demonstron dobësinë e RSA kur p dhe q janë shumë afër njëra-tjetrës.
2. Simplified SHA-1 (Opsioni 2)
Implementim i plotë i SHA-1 të thjeshtëzuar sipas specifikimit akademik:

Regjistrat 8-bit (H0=0x45, H1=0xAF, H2=0xAC, H3=0xFE)
Bloqe 32-bit, 16 raunde me 4 funksione f1..f4
Padding: msg || 1 || k zeros || L (16 bits)
Output: hash 32-bit (8 karaktere hex)
Modalitet debug për hap-pas-hapi

3. Preimage Attack (Opsioni 3)
Kërkon mesazh M' të tillë që H(M') = 4BAFE69C duke skanuar ASCII të printueshem (1-3 karaktere), kërkime të rastësishme dhe skanim paralel të gjithë hapësirës 4-byte me ExecutorService. Limite: 500,000 prova / 15 sekonda.
4. Second Preimage Attack (Opsioni 4)
Ndihmën e M nga përdoruesi, gjen M' ≠ M me H(M') = H(M) — demonstron mungesën e second preimage resistance në hash-et e dobët.
5. HMAC-Simplified-SHA1 (Opsioni 5)
Implementim i HMAC sipas formulës akademike:
HMAC(K, m) = H( (K' XOR ipad) || H( (K' XOR opad) || m ) )
me bllok-madhësi 4 byte, ipad=0x36, opad=0x5C dhe modalitet debug.
6. RSA Digital Signature (Opsioni 6)
Gjenerimi i çiftit të çelësave RSA (512-bit prime, e=65537), nënshkrimi i mesazhit me digest Simplified SHA-1 (sig = z^d mod n) dhe verifikimi (v = sig^e mod n).
