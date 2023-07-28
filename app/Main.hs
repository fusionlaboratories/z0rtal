{-# LANGUAGE OverloadedStrings #-}

module Main where

import Test.TestVectors
import BLS ( paramDST, paramDSTTest, hashToCurveG2, genPk, signMessage, verifySig )
import qualified Data.Curve.Weierstrass.BLS12381 as BLS1
import qualified Data.Curve.Weierstrass.BLS12381T as BLS2
import Data.Field.Galois ( toE )
import Data.Curve ( Point(..), mul )
import Data.Maybe (isNothing, fromJust)
import Control.Monad ( when )
import Data.Pairing
import Data.Pairing.BLS12381 ( G1', G2', Fr )
-- import qualified Data.ByteString.Char8 as BSC

-- Note: test vectors are found here: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-bls12381g2_xmdsha-256_sswu_

-- Stupid main that process the test vectors IF and ONLY IF the DST is set to the correct one
-- This is very trivial and should be fixed, I'm just rushing the PoC for now
main :: IO ()
main = do
    putStrLn "\nz0rtal - Zero Knowledge Portal (\"bridge\") for Ethereum"

    -- if paramDST == paramDSTTest
        -- then putStrLn $ "All tests pass: " ++ show testAll
        -- else putStrLn $ "DST is set to Prod DST, can't do the tests (TO FIX)"
    
    testSigs

-- Reminder: in Ethereum, private key is in Fr (scalar), public key is [sk]g1 so is in G1, while H(m) and signature are in G2
testSigs :: IO ()
testSigs = do
    putStrLn $ "Testing Pairing"
    
    -- p1 <- BLS1.rnd :: IO BLS1.PA
    -- p2 <- BLS2.rnd :: IO BLS2.PA

    let p1x = 287438181564476742670637172813879167770727845265441778952238642815148570632226348627900719345364160593094241355060
        p1y = 1458773885824975501936449986453807814813737899767280967671235252547783421571970757523445008003426095465594803910769
        mP1 = point p1x p1y :: Maybe G1' -- :: Maybe BLS1.PA

        --{-
        p2x = toE [ 237507355702515013865258943638646985757961490198631736979066942120573269221317757758600540496978686311481799894784
                  , 458973326312504573938332048807927562814324412973498445944491265510015216399640626137598335893982092206748809971598
                  ] :: BLS2.Fq2
        p2y = toE [ 1654472395384912352330754973187420649677076255606905616689682499692620231805863645498658845375236241611588803298707
                  , 1893428928556325975597422839205718513031347227635775045618622013114640405307180955749031781561418890273108852057008
                  ] :: BLS2.Fq2
        mP2 = point p2x p2y :: Maybe G2' -- :: Maybe BLS2.PA
        ---}

    when (isNothing mP1) $ do
        error "p1 is not a point on the curve!"
    
    when (isNothing mP2) $ do
        error "p2 is not a point on the curve!"
    
    {-
    let sk = 47107905128569135832754029587 :: Fr
        pk = gen `mul` sk :: G1'
        msg = "hello"
        hM = hashToCurveG2 msg :: G2'
        sig = hM `mul` sk
        -- verify = pairing gen (fromJust mP2) == pairing pk hM
        verify = pairing gen sig == pairing pk hM
    --}

    let sk = 47107905128569135832754029587 :: Fr
        pk = genPk sk
        msg = "hello"
        sig = signMessage sk msg
        verify = verifySig pk msg sig 
    putStrLn $ "verify = " ++ show verify

    -- let (p1, p2) = (fromJust mP1, fromJust mP2)
    -- let p1 = fromJust mP1

        -- pGt = pairing p1 p2
    
    -- putStrLn $ "e(p1, p2) = " ++ show pGt