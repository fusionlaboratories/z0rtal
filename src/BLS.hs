-- module BLS ( prime
--            , hashToField -- to test in ghci
--            , expandMessageXMD -- to test in ghci
--            , hashToCurveG2
--            , clearCofactorFast -- to test in ghci
--            , clearCofactor
--            , i2osp
--            , os2ip
--            , findV
--            ) where

module BLS where

import Data.Pairing.BLS12381 ( Fq, Fq2 )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Control.Exception ( assert )
import Data.Bits ( shiftL, shiftR, (.&.), xor )
import Crypto.Hash.SHA256 ( hash )
import Data.Field.Galois ( toE, fromE, (*^) )
import Data.Curve.Weierstrass.BLS12381T ( PA, Point(..), add, mul, frob, inv, mul' )
import Debug.Trace ( trace )
import Data.ByteString.Builder ( byteStringHex )
import Data.Curve ( dbl )
import GHC.Stack (HasCallStack)

-- | Making DST a type of itself to prevent mising with the actual message
type DST = ByteString

prime :: Integer
prime = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

-- | Security-bit target
paramK :: Int
paramK = 128

-- | The power of the extension field
paramM :: Int
paramM = 2

-- | Z param used for maping to curve (and 'sqrtRatio')
-- pre-computed here https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#suites-bls12381
paramZ :: Fq2
paramZ = toE [ -2, -1 ]

-- | Domain-separation-tag to orthogonalize hash functions
-- Be careful to select the right DST for prod vs for testing
paramDST :: DST
-- paramDST = paramDSTProd
paramDST = paramDSTTest

-- | DST used in Prod (check that it's correct with Ethereum impl)
paramDSTProd :: DST
paramDSTProd = BSC.pack "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"        -- Found in Typescript "ref implementation"

-- | DST used for testing RFC test vector
paramDSTTest :: DST
paramDSTTest = BSC.pack "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_" -- For testing against RFC test vector

-- | Cofactor-clearing param
-- hEff :: Fq
-- hEff = 0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551

-- | Take an aribitrary-length string of bytes and hash it to a point on the G2 curve
-- hashToCurveG2 :: ByteString -> Fq2
hashToCurveG2 :: ByteString -> PA
hashToCurveG2 msg =
    let [u0, u1] = hashToField msg 2

    -- Implementing the "naive", suboptimal version described here: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-encoding-byte-strings-to-el
    -- (it is suboptimal because it makes uses of isoMap twice and then add, while we could first add and then use isoMap once on the result.
    -- it SHOULD give the same answer)
        -- q0 = mapToCurveG2 u0
        -- q1 = mapToCurveG2 u1
        -- r = q0 `add` q1
        -- p = clearCofactor r
        -- p = clearCofactorFast r
    -- in p

    --{-
    -- TO DO
        q0' = mapToCurveSimpleSWU u0 -- This is NOT the q0 from the RFC test vector as we use the optimization
        q1' = mapToCurveSimpleSWU u1 -- This is NOT the q1 from the RFC test vector as we use the optimization
        r' = q0' `add` q1'
        r = isoMapG2 r'
        -- p = clearCofactor r
        p = clearCofactorFast r
    in p
    --}
    -- in error "needs mapToCurve"

-- | Takes an arbitrary length byte string and map them to N elements of the finite field
--   NOTE: this function is CORRECT (for m=2) as it was tested against the RFC test vector and the values reported for
--   u0 and u1 match (https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-bls12-381-g2-2)
hashToField :: ByteString -> Int -> [Fq2] -- Should it be [Fq] ? Or [Fq2]
hashToField msg count =
    -- let log2p = ceiling $ logBase 2 (fromInteger prime)
        -- l = ceiling (fromIntegral (log2p + paramK) / 8)
    -- let l = ceiling (fromIntegral (logBase 2 (fromInteger prime) + paramK) / 8)
    let l = ceiling $ fromIntegral (ceiling (logBase 2 (fromInteger prime)) + paramK) / 8
        lenInBytes = count * paramM * l
        dst = paramDST
        uniformBytes = expandMessageXMD msg dst lenInBytes
    in flip map [0..count-1] $ \i ->
        -- it's supposed to be a loop from 0 to m-1, but m = 2, so we do it by hand
        let elmOffset0 = l * (0 + i * paramM)
            tv0 = BS.take l (BS.drop elmOffset0 uniformBytes)
            e0 = os2ip tv0 `mod` prime
            elmOffset1 = l * (1 + i * paramM)
            tv1 = BS.take l (BS.drop elmOffset1 uniformBytes)
            e1 = os2ip tv1 `mod` prime
        in toE [fromIntegral e0, fromIntegral e1]

-- | Generates a uniformly-distributed random string of bytes from the input, whose length is specified
--   https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-expand_message_xmd
--   NOTE: this function was verified CORRECT with the test vectors from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-expand_message_xmdsha-256
expandMessageXMD :: ByteString -> DST -> Int -> ByteString
expandMessageXMD msg dst_ lenInBytes_ =
    -- If that triggers: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.3.3
    let dst = assert (BS.length dst_ <= 255) dst_
        lenInBytes = assert (lenInBytes_ <= 65535) lenInBytes_
        bInBytes = 32 -- we are using sha256 hash function, whose outputs is 32 bytes (256 bits)
        sInBytes = 64 -- we are using sha256 hash function, whose input block size is 64 bytes
        ell_ = ceiling (fromIntegral lenInBytes / fromIntegral bInBytes)
        ell = assert (ell_ <= 255) ell_
        dstPrime = dst <> i2osp (toInteger (BS.length dst)) 1
        zPad = i2osp 0 sInBytes
        lenInBytesStr = i2osp (toInteger lenInBytes) 2
        msgPrime = zPad <> msg <> lenInBytesStr <> i2osp 0 1 <> dstPrime
        b0 = hash msgPrime
        b1 = hash $ b0 <> i2osp 1 1 <> dstPrime
        bis = computeBis b0 b1 dstPrime ell
        uniformBytes = BS.concat (reverse bis)
    in BS.take lenInBytes uniformBytes
    where
        -- computeBis :: ByteString -> DST -> ByteString -> Int -> [ByteString]

        -- computeBis b0 dst b1 i
        computeBis :: ByteString -> ByteString -> DST -> Int -> [ByteString]
        computeBis b0 b1 dstPrime ell = foldl (\bis i -> hash (strxor b0 (head bis) <> i2osp i 1 <> dstPrime) : bis) [b1] [2..fromIntegral ell]

-- | Maps a point from the field Fq2 to the curve. This is the simplified SWU version for AB = 0.
--   It simply uses the simplified SWU version on input u to get a point on the isogenous curve E', and then
--   uses the isoMapG2 function to go from the point on E' to E.
mapToCurveG2 :: Fq2 -> PA
mapToCurveG2 u = let pointOnE' = mapToCurveSimpleSWU u
                 in isoMapG2 pointOnE'
-- mapToCurveG2 = isoMapG2 . mapToCurveSimpleSWU

-- | Straight-line implementation of the simplified SWU method.
--   Taken from version 16 of the draft: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-simplified-swu-method
--   NOTE: Originally, the code for Eth seemed to use version 11 of the draft (https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-G.2.3)
--   This version of the simplified map applies for curves for which A /= 0 and B /= 0. So let's remember that we are dealing with the isogenous
--   E' here, not E (hence the params in the where clause). In our usage, we will need to call isoMap on the result to get from E' to E
mapToCurveSimpleSWU :: Fq2 -> PA
mapToCurveSimpleSWU u =
    let tv1 = u^2
        tv1' = z * tv1
        -- tv1' = tv1 *^ z
        tv2 = tv1'^2
        tv2_2 = tv2 + tv1'
        tv3 = tv2_2 + 1
        tv3' = b * tv3
        tv4 = cmov z (-tv2_2) (tv2_2 /= 0)
        tv4' = a * tv4
        tv2_3 = tv3'^2
        tv6 = tv4'^2
        tv5 = a * tv6
        tv2_4 = tv2_3 + tv5
        tv2_5 = tv2_4 * tv3'
        tv6' = tv6 * tv4'
        tv5' = b * tv6'
        tv2_6 = tv2_5 + tv5'
        x = tv1' * tv3'
        (isGx1Square, y1) = sqrtRatio tv2_6 tv6'
        -- y = u *^ tv1'
        y = tv1' * u
        y_2 = y * y1
        x_2 = cmov x tv3' isGx1Square
        y_3 = cmov y_2 y1 isGx1Square
        e1 = sgn0M2 u == sgn0M2 y_3
        y_4 = cmov (-y_3) y_3 e1
        x_3 = x_2 / tv4'
    in  A x_3 y_4

    where
        z = paramZ
        b = toE [1012, 1012] -- param of the E' elliptic curve (not E!)
        a = toE [0, 240]     -- param of the E' elliptic curve (not E!)
        -- b = 4 -- param of the elliptic curve
        -- a = 0 -- param of the elliptic curve

-- | Utility function defined here https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-4
cmov :: a -> a -> Bool -> a
cmov x _ False = x
cmov _ y True = y

-- | Generic version of the sqrt_ratio defined here https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-F.2.1.1
--
sqrtRatio :: Fq2 -> Fq2 -> (Bool, Fq2)
sqrtRatio _ 0 = error "sqrtRatio u v needs v /= 0"
sqrtRatio u v =
    let c1 = 3 -- Largest c1 such that 2^c1 divides q-1
        c2 = (q - 1) `div` (2^c1)
        c3 = (c2 - 1) `div` 2
        c4 = 2^c1 - 1
        c5 = 2^(c1 - 1)
        c6 = z^c2
        c7 = z^((c2 + 1) `div` 2)
        -- Procedure
        tv1 = c6
        tv2 = v^c4
        tv3 = tv2^2
        tv3_2 = tv3 * v
        tv5 = u * tv3_2
        tv5_2 = tv5^c3
        tv5_3 = tv5_2 * tv2
        tv2_2 = tv5_3 * v
        tv3_3 = tv5_3 * u
        tv4 = tv3_3 * tv2_2
        tv5_4 = tv4^c5
        isQR = tv5_4 == 1
        tv2_3 = tv3_3 * c7
        tv5_5 = tv4 * tv1
        tv3_4 = cmov tv2_3 tv3_3 isQR
        tv4_2 = cmov tv5_5 tv4 isQR
        -- final_tv3 = loop c1 tv4_2 tv1 0
        final_tv3 = loop c1 tv4_2 tv1 tv3_4
    in (isQR, final_tv3)
    where
        q = prime ^ paramM
        z = paramZ
        loop :: Integer -> Fq2 -> Fq2 -> Fq2 -> Fq2
        loop 1 _ _ tv3 = tv3
        loop i tv4 tv1 tv3 = let tv5 = i - 2
                                 tv5_2 = 2^tv5
                                 tv5_3 = tv4^tv5_2
                                 e1 = tv5_3 == 1
                                 tv2 = tv3 * tv1
                                 tv1_2 = tv1 * tv1
                                 tv5_4 = tv4 * tv1_2
                                 newTv3 = cmov tv2 tv3 e1
                                 tv4_2 = cmov tv5_4 tv4 e1
                            --  in loop (i - 1) tv4_2 tv1 newTv3
                            in loop (i - 1) tv4_2 tv1_2 newTv3

-- NOTE: this function is verified CORRECT with some of the Javascript implentation.
isoMapG2 :: PA -> PA -- not exactly sure of this signature... we're going from points on E' to point on E
isoMapG2 O = O
isoMapG2 (A x' y') =
    -- let x = xNum / xDen
        -- y = y' * yNum / yDen
    if xDen == 0 || yDen == 0
        then O
        else 
            let x = xNum / xDen
                y = y' *^ yNum / yDen
            in A x y
    where
        xNum = k13 * x'^3 + k12 * x'^2 + k11 * x' + k10
        xDen = x'^2 + k21 * x' + k20
        yNum = k33 * x'^3 + k32 * x'^2 + k31 * x' + k30
        yDen = x'^3 + k42 * x'^2 + k41 * x' + k40
        k10 = toE [ 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6
                  , 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6
                  ]
        k11 = toE [ 0
                  , 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a
                  ]
        k12 = toE [ 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e
                  , 0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d
                  ]
        k13 = toE [ 0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1
                  , 0
                  ]
        k20 = toE [ 0
                  , 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63
                  ]
        k21 = toE [ 0xc
                  , 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f
                  ]
        k30 = toE [ 0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706
                  , 0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706
                  ]
        k31 = toE [ 0
                  , 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be
                  ]
        k32 = toE [ 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c
                  , 0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f
                  ]
        k33 = toE [ 0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10
                  , 0
                  ]
        k40 = toE [ 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb
                  , 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb
                  ]
        k41 = toE [ 0
                  , 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3
                  ]
        k42 = toE [ 0x12
                  , 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99
                  ]

-- | Maps a point on the elliptic curve to the group G. This is called clearing the cofactor.
--   We are using the general approach here which simply performs a scalar multiplication by hEff
--   Once we have this implementation working, we might want to look into the faster, BLS12-381-optimized version of that
--   method with the Frobenius endomorphism as described here: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#clear-cofactor-bls12381-g2
-- NOTE: this currently DOES NOT produce the same value as the Fast method, I don't know why.
-- We should probablty ditch it
-- clearCofactor :: PA -> PA
-- clearCofactor p = p `mul` hEff

-- | NOTE: This function has been verified CORRECT with test vectors
clearCofactorFast :: PA -> PA
clearCofactorFast p =
    -- /!\ WARNING !
    -- We CANNOT use let c1 = -15132376222941642752 and then use p `mul` c1.
    -- It took me forever to track this down, but the correct way to do it is to use the positive value c1 = 15132376222941642752
    --, then do the multiplication p `mul` c1 and then negate / take the `inv` of the result...
    -- let c1 = -15132376222941642752  -- BLS12-381 parameter (-0xd201000000010000)
    let c1' = 15132376222941642752
        t1 = inv (p `mul` c1')
        t2 = psi p
        -- t3 = p `mul` 2
        t3 = dbl p
        t3_2 = psi2 t3
        t3_3 = t3_2 `add` inv t2 -- t3_3 = t3_2 - t2
        t2_2 = t1 `add` t2 -- t2_2 = t1 + t2
        t2_3 = inv (t2_2 `mul` c1') -- here's the trick again
        t3_4 = t3_3 `add` t2_3 -- t3_4 = t3_3 + t2_3
        t3_5 = t3_4 `add` inv t1 -- t3_5 = t3_4 - t1
        q = t3_5 `add` inv p -- q = t3_5 - p
    in q
    -- where

--{-

--Commented because Data.Curve provides `frob` which computes the frobenius endomorphism on a POINT (frobienius function under
--computes it on a POINT in the field ; but from my understanding of the way it's used in 'clearCofactorFast', we really want to
--compute the frobenius endophorism of a POINT)

frobenius :: Fq2 -> Fq2
frobenius x = let [x0, x1] = fromE x
                in toE [x0, -x1]

psi :: PA -> PA
psi O       = error "psi::O not handled (should return O as well?)"
psi (A x y) = let base = toE [ 1, 1 ] :: Fq2
                  c1 = 1 / base^((prime - 1) `div` 3)
                  c2 = 1 / base^((prime - 1) `div` 2)
                  qx = c1 * frobenius x
                  qy = c2 * frobenius y
                in A qx qy

psi2 :: PA -> PA
psi2 O       = error "psi2::O not handlded (should return O as well?)"
psi2 (A x y) = let c1 = 1 / 2^((prime - 1) `div` 3)
                   qx = c1 * x
                   qy = -y
                in A qx qy
---}        

-- | m=2 specilized version of the "sign" sgn0 utility function
-- Definition here: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-the-sgn0-function
sgn0M2 :: Fq2 -> Bool
sgn0M2 x = let [x0, x1] = fromE x
            --    sign0 = (x0 `mod` 2) == 1
            --    zero0 = x0 == 0
            --    sign1 = (x1 `mod` 2) == 1
               sign0 = (toInteger x0 `mod` 2) == 1
               zero0 = toInteger x0 == 0
               sign1 = (toInteger x1 `mod` 2) == 1
               s = sign0 || (zero0 && sign1)
            in s

sgn0M1 :: Fq -> Bool
sgn0M1 x = (x `mod` 2) == 1

-- | Convert a non-negative integer to an octet string of specified length
i2osp :: Integer -> Int -> ByteString
i2osp value length' | value < 0 = error "i2osp: only positive values are supported"
                   | value >= shiftL 1 (8 * length') = error $ "i2osp: " ++ show value ++ " cannot fit in " ++ show length' ++ " bytes!"
                    | otherwise = BS.pack $ reverse $ go (length' - 1) value
    where go 0 val = [fromInteger (val .&. 0xFF)]
          go n val = fromInteger (val .&. 0xFF) : go (n-1) (shiftR val 8)

-- | convert an octet string (big endian) to an integer
os2ip :: ByteString -> Integer
os2ip bstr = foldl (\acc byte -> shiftL acc 8 + toInteger byte) 0 (BS.unpack bstr)

-- | Return the bitwise XOR of two bytestrings
strxor :: ByteString -> ByteString -> ByteString
strxor bstr1 bstr2 | BS.length bstr1 /= BS.length bstr2 = error "strxor: byte strings don't have the same length"
                   | otherwise = BS.pack $ BS.zipWith xor bstr1 bstr2

findV :: Integer -> Integer -> Integer
findV q_1 0 = error "could not find"
findV q_1 v | q_1 `rem` (2^v) == 0 = v
            | otherwise        = findV q_1 (v-1)