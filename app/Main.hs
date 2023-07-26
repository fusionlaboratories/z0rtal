module Main where

import BLS
import Data.Curve.Weierstrass.BLS12381T ( PA, Point(..), add )
-- import Control.Exception ( assert )
-- import Data.ByteString ( ByteString )
-- import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

-- Note: test vectors are found here: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-bls12381g2_xmdsha-256_sswu_

main :: IO ()
main = do
    let msg = BSC.pack "abc"
        myP = hashToCurveG2 msg
        theirP = (A px' py') :: PA
    putStrLn $ "msg = " ++ show msg
    putStrLn $ "myP == theirP : " ++ show (myP == theirP)