module Main where

import BLS
import Data.Curve.Weierstrass.BLS12381T ( PA, Point(..), add )
import Control.Exception ( assert )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

-- Note: test vectors are found here: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-bls12381g2_xmdsha-256_sswu_

main :: IO ()
main = do
  -- This test the top-level `hashToCurveG2` function
  let msg = BSC.pack ""
      p@(A px py) = hashToCurveG2 msg
      p' = A px' py'
  print $ p == p' -- to match point
  -- print $ px == px' -- to match individual coordinates
  -- print $ py == py' -- to match individual coordinates

  -- This tests the 'clearCofactor' function(s)
  let q0 = A q0x' q0y' :: PA
      q1 = A q1x' q1y' :: PA
      r = q0 `add` q1
      p@(A px py) = clearCofactor r      -- using the naive, scalar multiplication version
      -- p@(A px py) = clearCofactorFast r  -- using the facter version with the frobenius endomorphism (they are supposed to be equal)
      p' = A px' py'
  -- That tests that ou point p computed with ou call to clearCofactor matches their point P given in the test vector
  print $ p == p'
  -- assert (px == px') -- if we want to match on individual coordinates
  --assert (py == py') -- if we want to match on individual coordinates