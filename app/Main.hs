module Main where

import BLS
-- import qualified Data.ByteString as BS

main :: IO ()
main = do
  let val = 100000
      n = 5
  print $ os2ip (i2osp val n) == val
