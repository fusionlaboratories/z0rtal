module Main where

import Test.TestVectors
import BLS (paramDST, paramDSTTest)

-- Note: test vectors are found here: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-bls12381g2_xmdsha-256_sswu_

-- Stupid main that process the test vectors IF and ONLY IF the DST is set to the correct one
-- This is very trivial and should be fixed, I'm just rushing the PoC for now
main :: IO ()
main = do
    putStrLn "\nz0rtal - Zero Knowledge Portal (\"bridge\") for Ethereum"

    if paramDST == paramDSTTest
        then putStrLn $ "All tests pass: " ++ show testAll
        else putStrLn $ "DST is set to Prod DST, can't do the tests (TO FIX)"