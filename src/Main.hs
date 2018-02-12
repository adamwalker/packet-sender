{-# LANGUAGE RecordWildCards #-}

module Main where

import Data.Monoid
import Data.Word
import Data.Void
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char
import Data.Bifunctor
import Control.Monad

import Text.Megaparsec
import Text.Megaparsec.Char
import qualified Text.Megaparsec.Char.Lexer as L
import Hexdump
import Network.Pcap
import Options.Applicative

data Options = Options {
    intf    :: String,
    verbose :: Bool,
    dryRun  :: Bool,
    toSend  :: ByteString
}

space' = L.space space1 (L.skipLineComment "//") (L.skipBlockComment "/*" "*/")

lexeme = L.lexeme space'

symbol = L.symbol space'

parens = between (symbol "(") (symbol ")")

quotes = between (symbol "\"") (symbol "\"")

decimal = lexeme L.decimal

hexPair :: Parsec Void String Word8
hexPair = do
    c1 <- hexDigitChar
    c2 <- hexDigitChar
    return $ fromIntegral (digitToInt c1) * 16 + fromIntegral (digitToInt c2)

expression 
    =   concat <$> (replicate <$> (try (decimal <* symbol "*")) <*> expressions)
    <|> quotes (many (fromIntegral . digitToInt <$> (notChar '"')))
    <|> lexeme (pure <$> hexPair)
    <|> parens expressions

expressions = concat <$> some expression

topParser :: Parsec Void String ByteString
topParser = do
    res <- expressions
    eof
    return $ BS.pack res

dataOptionParser :: ReadM ByteString
dataOptionParser = eitherReader $ first parseErrorPretty . parse topParser "STDIN"

func Options{..} = do

    when verbose $ putStrLn $ "\n" ++ prettyHex toSend

    unless dryRun $ do

        -- open device
        dev <- openLive intf 65535 False 0

        -- send
        sendPacketBS dev toSend

main = customExecParser (prefs $ showHelpOnError) opts >>= {- runExceptT  . -} func -- >>= printErr
    where 
    opts = info (helper <*> parseOpts) (fullDesc <> header "packet-sender")

    parseOpts 
        =   Options
        <$> strOption (short 'i' <> long "intf" <> metavar "INTF" <> help "Interface")
        <*> switch (short 'v' <> long "verbose" <> help "Print the packet contents to stdout before sending")
        <*> switch (short 'n' <> long "dry-run" <> help "Don't actually send the packet")
        <*> argument dataOptionParser (metavar "DATA")

    --printErr (Left err) = putStrLn err
    --printErr (Right _)  = return ()

