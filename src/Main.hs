{-# LANGUAGE RecordWildCards #-}

module Main where

import Network.Pcap
import Options.Applicative
import Data.Monoid
import Data.Word
import Data.Void
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char
import Data.Bifunctor

import Text.Megaparsec
import Text.Megaparsec.Char
import qualified Text.Megaparsec.Char.Lexer as L

data Options = Options {
    intf   :: String,
    toSend :: ByteString
}

lexeme = L.lexeme $ L.space space1 (L.skipLineComment "//") (L.skipBlockComment "/*" "*/")

hexPair :: Parsec Void String Word8
hexPair = do
    c1 <- hexDigitChar
    c2 <- hexDigitChar
    return $ fromIntegral (digitToInt c1) * 16 + fromIntegral (digitToInt c2)

topParser :: Parsec Void String ByteString
topParser = do
    res <- many $ lexeme hexPair
    eof
    return $ BS.pack res

dataOptionParser :: ReadM ByteString
dataOptionParser = eitherReader $ first show . parse topParser "STDIN"

func Options{..} = do

    print $ toSend

    -- open device
    dev <- openLive intf 65535 False 0

    -- send
    sendPacketBS dev toSend

main = execParser opts >>= {- runExceptT  . -} func -- >>= printErr
    where 
    opts = info (helper <*> parseOpts) (fullDesc <> header "packet-sender")

    parseOpts 
        =   Options
        <$> strOption (short 'i' <> metavar "INTF" <> help "Interface")
        <*> argument dataOptionParser (metavar "DATA")

    --printErr (Left err) = putStrLn err
    --printErr (Right _)  = return ()

